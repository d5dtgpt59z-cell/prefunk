import AppKit
import Foundation
import UniformTypeIdentifiers

@main
struct DropProviderRegression {
    static func main() async throws {
        let folder = FileManager.default.temporaryDirectory
            .appendingPathComponent("prefunk-drop-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }

        guard let provider = NSItemProvider(contentsOf: folder) else {
            throw DropFailure("Could not create a Finder-style folder provider.")
        }
        guard provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) else {
            throw DropFailure("Folder provider did not advertise a file URL.")
        }

        let data: Data = try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data, Error>) in
            provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: DropFailure("Folder provider returned no URL data."))
                }
            }
        }

        guard let decoded = URL(dataRepresentation: data, relativeTo: nil),
              try decoded.resourceValues(forKeys: [URLResourceKey.isDirectoryKey]).isDirectory == true else {
            throw DropFailure("Dropped file URL did not decode as a folder.")
        }
        print("Drop provider regression passed: Finder folder URL decoded correctly.")
    }
}

struct DropFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
