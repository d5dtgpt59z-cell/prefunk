import AppKit
import Foundation
import PrefunkCore

@MainActor
final class AppModel: ObservableObject {
    @Published var summary: ScanSummary?
    @Published var selectedFinding: Finding?
    @Published var isScanning = false
    @Published var errorMessage: String?
    @Published var copiedFindingID: UUID?
    @Published var copiedAgentReport = false

    func chooseAndScanFolder() {
        let panel = NSOpenPanel()
        panel.title = "Choose a project to scan"
        panel.message = "Prefunk reads supported text files locally. Your code is not uploaded."
        panel.prompt = "Scan Project"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false

        guard panel.runModal() == .OK, let url = panel.url else { return }
        scan(url)
    }

    func scan(_ url: URL) {
        isScanning = true
        errorMessage = nil
        selectedFinding = nil

        Task.detached(priority: .userInitiated) {
            let result = ProjectScanner().scan(rootURL: url)
            await MainActor.run {
                self.summary = result
                self.selectedFinding = result.findings.first
                self.isScanning = false
            }
        }
    }

    func copyFixPrompt(for finding: Finding) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(finding.fixPrompt, forType: .string)
        copiedFindingID = finding.id
        Task {
            try? await Task.sleep(for: .seconds(2))
            if copiedFindingID == finding.id {
                copiedFindingID = nil
            }
        }
    }

    func copyAgentPreflight() {
        guard let summary, let prompt = try? PrefunkExport.guardedPrompt(for: summary) else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(prompt, forType: .string)
        copiedAgentReport = true
        Task {
            try? await Task.sleep(for: .seconds(2))
            copiedAgentReport = false
        }
    }

    func exportAgentJSON() {
        guard let summary else { return }
        let panel = NSSavePanel()
        panel.title = "Export Agent Preflight"
        panel.nameFieldStringValue = "\(summary.rootURL.lastPathComponent)-prefunk.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try PrefunkExport.jsonData(for: summary).write(to: url, options: .atomic)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func exportReport() {
        guard let summary else { return }
        let panel = NSSavePanel()
        panel.title = "Export Security Report"
        panel.nameFieldStringValue = "\(summary.rootURL.lastPathComponent)-security-report.md"
        panel.allowedContentTypes = [.plainText]

        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try summary.markdown.write(to: url, atomically: true, encoding: .utf8)
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
