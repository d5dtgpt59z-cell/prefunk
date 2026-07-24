import AppKit
import Foundation
import PrefunkCore
import UniformTypeIdentifiers

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

    func startNewScan() {
        summary = nil
        selectedFinding = nil
        errorMessage = nil
        copiedFindingID = nil
        copiedAgentReport = false
    }

    func handleDrop(providers: [NSItemProvider]) -> Bool {
        guard let provider = providers.first(where: {
            $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier)
        }) else {
            errorMessage = "Drop a project folder from Finder."
            return false
        }

        provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { [weak self] data, error in
            Task { @MainActor in
                guard let self else { return }
                guard error == nil, let data,
                      let url = URL(dataRepresentation: data, relativeTo: nil) else {
                    self.errorMessage = "Prefunk couldn’t read that dropped item. Try Choose a project instead."
                    return
                }

                do {
                    let values = try url.resourceValues(forKeys: [.isDirectoryKey])
                    guard values.isDirectory == true else {
                        self.errorMessage = "Drop a project folder, not an individual file."
                        return
                    }
                    self.scan(url)
                } catch {
                    self.errorMessage = "Prefunk couldn’t open that folder. Try Choose a project instead."
                }
            }
        }
        return true
    }

    func scan(_ url: URL) {
        isScanning = true
        errorMessage = nil
        selectedFinding = nil

        Task.detached(priority: .userInitiated) {
            let accessed = url.startAccessingSecurityScopedResource()
            defer {
                if accessed {
                    url.stopAccessingSecurityScopedResource()
                }
            }
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
