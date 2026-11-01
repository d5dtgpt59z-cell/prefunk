import Foundation
import PrefunkCore

enum CLIError: Error, CustomStringConvertible {
    case usage(String)
    var description: String {
        switch self {
        case .usage(let message): message
        }
    }
}

@main
struct PrefunkCLI {
    static func main() {
        do {
            let options = try Options(arguments: Array(CommandLine.arguments.dropFirst()))
            let summary = ProjectScanner().scan(rootURL: options.root)
            let data: Data
            switch options.format {
            case .json:
                data = try PrefunkExport.jsonData(for: summary, projectName: options.projectName)
            case .prompt:
                data = Data(try PrefunkExport.guardedPrompt(
                    for: summary,
                    projectName: options.projectName
                ).utf8)
            case .markdown:
                data = Data(summary.markdown(
                    projectName: options.projectName ?? summary.clientSafeProjectName
                ).utf8)
            }

            if let output = options.output {
                try data.write(to: output, options: .atomic)
                FileHandle.standardError.write(Data("Prefunk wrote \(output.lastPathComponent)\n".utf8))
            } else {
                FileHandle.standardOutput.write(data)
                FileHandle.standardOutput.write(Data("\n".utf8))
            }

            if summary.coverage.hasGaps { exit(3) }
            if !summary.findings.isEmpty { exit(2) }
            exit(0)
        } catch {
            FileHandle.standardError.write(Data("prefunk: \(error)\n".utf8))
            exit(64)
        }
    }
}

private struct Options {
    enum Format: String { case json, prompt, markdown }
    let root: URL
    let format: Format
    let output: URL?
    let projectName: String?

    init(arguments: [String]) throws {
        if arguments.contains("--help") || arguments.contains("-h") {
            throw CLIError.usage(Self.help)
        }
        var values = arguments
        if values.first == "scan" { values.removeFirst() }
        var path: String?
        var format = Format.json
        var output: URL?
        var projectName: String?
        var index = 0
        while index < values.count {
            switch values[index] {
            case "--format":
                index += 1
                guard index < values.count, let parsed = Format(rawValue: values[index]) else {
                    throw CLIError.usage("--format must be json, prompt, or markdown")
                }
                format = parsed
            case "--output":
                index += 1
                guard index < values.count else { throw CLIError.usage("--output requires a file path") }
                output = URL(fileURLWithPath: values[index]).standardizedFileURL
            case "--project-name":
                index += 1
                guard index < values.count else { throw CLIError.usage("--project-name requires a display name") }
                let value = values[index].trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty else { throw CLIError.usage("--project-name cannot be empty") }
                projectName = value
            default:
                guard !values[index].hasPrefix("-"), path == nil else {
                    throw CLIError.usage("Unknown argument: \(values[index])\n\n\(Self.help)")
                }
                path = values[index]
            }
            index += 1
        }
        let candidate = URL(fileURLWithPath: path ?? FileManager.default.currentDirectoryPath).standardizedFileURL
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: candidate.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw CLIError.usage("Scan root is not a readable directory.")
        }
        root = candidate
        self.format = format
        self.output = output
        self.projectName = projectName
    }

    static let help = """
    Usage: prefunk scan [project-path] [--format json|prompt|markdown] [--output file]
                        [--project-name "Client-safe name"]

    Exit codes:
      0  No rule matches and complete supported-file coverage
      2  Potential findings detected
      3  Incomplete coverage (with or without findings)
      64 Usage or fatal scan error
    """
}
