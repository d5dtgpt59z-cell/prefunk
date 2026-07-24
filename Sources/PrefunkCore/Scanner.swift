import CryptoKit
import Foundation

struct ScanRule {
    let id: String
    let severity: Severity
    let title: String
    let explanation: String
    let remediation: String
    let pattern: String
    let fileNamePattern: String?
    let options: NSRegularExpression.Options
    let requiresSupabaseServiceRoleJWT: Bool

    init(id: String, severity: Severity, title: String, explanation: String, remediation: String,
         pattern: String, fileNamePattern: String? = nil,
         options: NSRegularExpression.Options = [], requiresSupabaseServiceRoleJWT: Bool = false) {
        self.id = id; self.severity = severity; self.title = title; self.explanation = explanation
        self.remediation = remediation; self.pattern = pattern; self.fileNamePattern = fileNamePattern
        self.options = options; self.requiresSupabaseServiceRoleJWT = requiresSupabaseServiceRoleJWT
    }
}

public struct ProjectScanner {
    public init() {}
    private let excludedDirectories: Set<String> = [
        ".git", ".build", "build", "DerivedData", "node_modules", "Pods", ".next", "dist", "vendor"
    ]
    private let allowedExtensions: Set<String> = [
        "js", "jsx", "ts", "tsx", "json", "swift", "py", "rb", "go", "java", "kt",
        "env", "yaml", "yml", "toml", "xml", "plist", "rules", "md", "txt", "conf"
    ]
    private let maxFileBytes = 2_000_000
    private let maxAggregateBytes = 200_000_000
    private let maxCandidateFiles = 50_000

    private let rules: [ScanRule] = [
        .init(id: "secret-openai-key", severity: .critical, title: "Possible OpenAI API key in source",
              explanation: "A usable API key in source code can be extracted and abused.",
              remediation: "Revoke it, remove it from history, and store its replacement outside client code.",
              pattern: #"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"#),
        .init(id: "secret-github-token", severity: .critical, title: "Possible GitHub token in source",
              explanation: "A GitHub token may grant repository, workflow, package, or organization access.",
              remediation: "Revoke it, remove it from history, and use a secret manager.",
              pattern: #"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})"#),
        .init(id: "secret-aws-access-key", severity: .critical, title: "Possible AWS access key in source",
              explanation: "Exposed cloud credentials can allow unauthorized infrastructure or data access.",
              remediation: "Disable it, review audit logs, rotate related secrets, and use an approved credential provider.",
              pattern: #"(?:AKIA|ASIA)[A-Z0-9]{16}"#),
        .init(id: "secret-private-key", severity: .critical, title: "Private key material in project",
              explanation: "Private keys can enable impersonation, decryption, or unauthorized access.",
              remediation: "Remove and rotate it, purge history, and use protected key storage.",
              pattern: #"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"#),
        .init(id: "client-secret-variable", severity: .high, title: "Secret-like value may be exposed to client code",
              explanation: "Public frontend variables are bundled into the client and cannot protect privileged credentials.",
              remediation: "Move privileged access server-side and keep secrets in server-only configuration.",
              pattern: #"(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|ADMIN_KEY)\s*[:=]\s*["']?[^"'\s]{6,}"#,
              options: [.caseInsensitive]),
        .init(id: "cors-wildcard", severity: .medium, title: "Wildcard CORS configuration needs review",
              explanation: "A wildcard origin may expose an API to unintended websites depending on credentials and response sensitivity.",
              remediation: "Confirm the endpoint is intentionally public or use an explicit trusted-origin allowlist.",
              pattern: #"(?:Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origin\s*:\s*["']\*["'])"#,
              options: [.caseInsensitive]),
        .init(id: "firebase-open-rules", severity: .critical, title: "Firebase rule may allow public access",
              explanation: "An unconditional allow rule can permit public reads or writes.",
              remediation: "Require authentication plus appropriate ownership or role checks.",
              pattern: #"allow\s+(?:read|write|read,\s*write)\s*:\s*if\s+true\s*;"#,
              fileNamePattern: #"(?:firestore|storage)\.rules$"#, options: [.caseInsensitive]),
        .init(id: "supabase-service-role-jwt", severity: .critical, title: "Supabase service-role JWT may be exposed",
              explanation: "A service-role JWT bypasses Row Level Security and must never ship in client code.",
              remediation: "Rotate it and keep the replacement server-side only.",
              pattern: #"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"#,
              requiresSupabaseServiceRoleJWT: true),
        .init(id: "supabase-service-role-variable", severity: .high, title: "Possible Supabase service-role variable",
              explanation: "A service-role variable assignment may expose a privileged key and needs confirmation.",
              remediation: "Confirm the value is not committed or client-bundled; rotate it if exposed.",
              pattern: #"SUPABASE_SERVICE_ROLE_KEY\s*[:=]\s*["']?[A-Za-z0-9_.-]{20,}"#, options: [.caseInsensitive]),
        .init(id: "hardcoded-password", severity: .high, title: "Possible hardcoded password",
              explanation: "A password assigned in source or configuration can leak through history or bundles.",
              remediation: "Confirm it is a real credential, then move and rotate it using protected runtime configuration.",
              pattern: #"(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#, options: [.caseInsensitive])
    ]

    public func scan(rootURL: URL) -> ScanSummary {
        var coverage = ScanCoverage()
        let files = candidateFiles(in: rootURL, coverage: &coverage)
        let compiled = rules.compactMap { rule -> (ScanRule, NSRegularExpression)? in
            guard let regex = try? NSRegularExpression(pattern: rule.pattern, options: rule.options) else { return nil }
            return (rule, regex)
        }
        var findings: [Finding] = []
        var findingIndex: [String: Int] = [:]
        var aggregateBytes = 0

        for fileURL in files {
            guard let values = try? fileURL.resourceValues(forKeys: [.fileSizeKey]),
                  let size = values.fileSize else { coverage.unreadable += 1; continue }
            guard size <= maxFileBytes else { coverage.oversized += 1; continue }
            guard aggregateBytes + size <= maxAggregateBytes else { coverage.workLimitReached = true; break }
            guard let data = try? Data(contentsOf: fileURL, options: [.mappedIfSafe]) else {
                coverage.unreadable += 1; continue
            }
            guard let content = String(data: data, encoding: .utf8) else {
                coverage.decodeFailures += 1; continue
            }
            aggregateBytes += size
            coverage.scanned += 1
            let relativePath = relativePath(for: fileURL, rootURL: rootURL)

            for (rule, regex) in compiled {
                if let filePattern = rule.fileNamePattern,
                   relativePath.range(of: filePattern, options: [.regularExpression, .caseInsensitive]) == nil { continue }
                let fullRange = NSRange(content.startIndex..., in: content)
                for match in regex.matches(in: content, range: fullRange) {
                    guard let swiftRange = Range(match.range, in: content) else { continue }
                    let matched = String(content[swiftRange])
                    guard !isObviousPlaceholder(matched),
                          !rule.requiresSupabaseServiceRoleJWT || isServiceRoleJWT(matched) else { continue }
                    let line = content[..<swiftRange.lowerBound].reduce(into: 1) { if $1 == "\n" { $0 += 1 } }
                    let location = FindingLocation(relativePath: relativePath, line: line)
                    let fingerprint = matchFingerprint(ruleID: rule.id, match: matched)
                    let matchConfidence = confidence(for: rule.id, relativePath: relativePath)
                    if let index = findingIndex[fingerprint] {
                        findings[index].addLocation(location, confidence: matchConfidence)
                    } else {
                        findingIndex[fingerprint] = findings.count
                        findings.append(Finding(ruleID: rule.id, severity: rule.severity,
                            confidence: matchConfidence, title: rule.title,
                            explanation: rule.explanation, remediation: rule.remediation,
                            relativePath: relativePath, line: line, evidence: "[redacted \(rule.id)]"))
                    }
                }
            }
        }
        findings.sort {
            if $0.severity != $1.severity { return $0.severity > $1.severity }
            if $0.confidence != $1.confidence { return $0.confidence > $1.confidence }
            return $0.location < $1.location
        }
        return ScanSummary(rootURL: rootURL, coverage: coverage, findings: findings, finishedAt: Date())
    }

    private func candidateFiles(in rootURL: URL, coverage: inout ScanCoverage) -> [URL] {
        final class ErrorCounter { var value = 0 }
        let errors = ErrorCounter()
        guard let enumerator = FileManager.default.enumerator(at: rootURL,
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey],
            options: [], errorHandler: { _, _ in
                errors.value += 1
                return true
            }) else { coverage.enumerationFailed = true; return [] }
        var files: [URL] = []
        for case let url as URL in enumerator {
            if excludedDirectories.contains(url.lastPathComponent) {
                coverage.excludedDirectoryRoots += 1; enumerator.skipDescendants(); continue
            }
            guard let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else {
                coverage.unreadable += 1; continue
            }
            if values.isSymbolicLink == true {
                coverage.unsupported += 1
                enumerator.skipDescendants()
                continue
            }
            guard values.isRegularFile == true else { continue }
            let supported = allowedExtensions.contains(url.pathExtension.lowercased()) || url.lastPathComponent.hasPrefix(".env")
            guard supported else { coverage.unsupported += 1; continue }
            guard files.count < maxCandidateFiles else { coverage.workLimitReached = true; break }
            files.append(url)
        }
        coverage.traversalErrors += errors.value
        return files
    }

    private func relativePath(for fileURL: URL, rootURL: URL) -> String {
        let root = rootURL.standardizedFileURL.path
        let file = fileURL.standardizedFileURL.path
        guard file == root || file.hasPrefix(root + "/") else { return fileURL.lastPathComponent }
        return String(file.dropFirst(root.count)).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    }

    private func matchFingerprint(ruleID: String, match: String) -> String {
        let digest = SHA256.hash(data: Data("\(ruleID)\u{0}\(match)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func isObviousPlaceholder(_ match: String) -> Bool {
        let lower = match.lowercased()
        if ["example", "placeholder", "changeme", "your_", "dummy", "fake_token"].contains(where: lower.contains) { return true }
        let compact = match.filter(\.isLetter)
        return compact.count > 12 && Set(compact.lowercased()).count == 1
    }

    private func isServiceRoleJWT(_ token: String) -> Bool {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return false }
        var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        payload += String(repeating: "=", count: (4 - payload.count % 4) % 4)
        guard let data = Data(base64Encoded: payload),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return false }
        return object["role"] as? String == "service_role"
    }

    private func confidence(for ruleID: String, relativePath: String) -> Confidence {
        let components = relativePath.lowercased().split(separator: "/").map(String.init)
        let nonProduction = Set(["test", "tests", "__tests__", "fixture", "fixtures", "example", "examples",
                                 "sample", "samples", "spec", "specs", "snapshot", "snapshots", "docs"])
        if relativePath.lowercased().hasSuffix(".md") || relativePath.lowercased().hasSuffix(".txt") ||
            !nonProduction.isDisjoint(with: components) { return .low }
        if ruleID == "cors-wildcard" || ruleID == "hardcoded-password" ||
            ruleID == "supabase-service-role-variable" { return .medium }
        return .high
    }
}
