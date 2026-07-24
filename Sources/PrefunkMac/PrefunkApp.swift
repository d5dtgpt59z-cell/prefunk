import SwiftUI

@main
struct PrefunkApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
        }
        .defaultSize(width: 1200, height: 800)
        .windowStyle(.titleBar)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("New Scan") {
                    model.startNewScan()
                }
                .keyboardShortcut("n")
                .disabled(model.summary == nil)
                Button("Scan Project Folder…") {
                    model.chooseAndScanFolder()
                }
                .keyboardShortcut("o")
                Button("Export Report…") {
                    model.exportReport()
                }
                .keyboardShortcut("e")
                .disabled(model.summary == nil)
            }
        }
    }
}
