import SwiftUI
import PrefunkCore

private enum Brand {
    static let background = Color(red: 0.045, green: 0.045, blue: 0.055)
    static let sidebar = Color(red: 0.055, green: 0.052, blue: 0.065)
    static let surface = Color.white.opacity(0.055)
    static let surfaceStrong = Color.white.opacity(0.09)
    static let border = Color.white.opacity(0.12)
    static let muted = Color.white.opacity(0.58)
    static let purple = Color(red: 0.66, green: 0.34, blue: 0.95)
    static let lilac = Color(red: 0.80, green: 0.56, blue: 1.0)
}

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(spacing: 0) {
            JourneySidebar(hasResults: model.summary != nil)
                .frame(width: 280)

            ZStack {
                Brand.background
                if let summary = model.summary {
                    ResultsView(summary: summary)
                } else {
                    WelcomeView()
                }
            }
        }
        .frame(minWidth: 1040, minHeight: 700)
        .preferredColorScheme(.dark)
        .background(Brand.background)
        .alert("Prefunk", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
    }
}

private struct JourneySidebar: View {
    let hasResults: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "checkmark.shield.fill")
                    .font(.system(size: 30))
                    .symbolRenderingMode(.palette)
                    .foregroundStyle(.white, Brand.purple)
                Text("Prefunk")
                    .font(.system(size: 24, weight: .bold, design: .rounded))
            }
            .padding(.bottom, 54)

            StepRow(
                number: 1,
                title: "Choose your project",
                subtitle: "Pick a folder or drag it in",
                state: hasResults ? .complete : .active
            )
            StepConnector(complete: hasResults)
            StepRow(
                number: 2,
                title: "We check it safely",
                subtitle: "Nothing is uploaded or run",
                state: hasResults ? .complete : .upcoming
            )
            StepConnector(complete: hasResults)
            StepRow(
                number: 3,
                title: "Get clear fixes",
                subtitle: "Understand issues and fix them",
                state: hasResults ? .active : .upcoming
            )

            Spacer()

            VStack(alignment: .leading, spacing: 8) {
                Label("Your code never leaves\nyour Mac.", systemImage: "lock.fill")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(.white.opacity(0.78))
                    .lineSpacing(3)
                Text("Nothing is uploaded or run.")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Brand.lilac)
            }
        }
        .padding(.horizontal, 30)
        .padding(.vertical, 34)
        .background(Brand.sidebar)
        .overlay(alignment: .trailing) {
            Rectangle()
                .fill(Brand.border)
                .frame(width: 1)
        }
    }
}

private enum StepState {
    case active
    case complete
    case upcoming
}

private struct StepRow: View {
    let number: Int
    let title: String
    let subtitle: String
    let state: StepState

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Circle()
                    .fill(circleFill)
                Circle()
                    .stroke(circleStroke, lineWidth: 1)
                if state == .complete {
                    Image(systemName: "checkmark")
                        .font(.system(size: 12, weight: .bold))
                } else {
                    Text("\(number)")
                        .font(.system(size: 14, weight: .semibold))
                }
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(state == .upcoming ? .white.opacity(0.74) : .white)
                Text(subtitle)
                    .font(.system(size: 13))
                    .foregroundStyle(Brand.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.top, 1)
        }
        .padding(.vertical, state == .active ? 15 : 6)
        .padding(.horizontal, state == .active ? 12 : 0)
        .background {
            if state == .active {
                RoundedRectangle(cornerRadius: 10)
                    .fill(Brand.surfaceStrong)
                    .overlay(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 2)
                            .fill(Brand.purple)
                            .frame(width: 3)
                    }
            }
        }
    }

    private var circleFill: Color {
        switch state {
        case .active: Brand.purple
        case .complete: Brand.purple.opacity(0.75)
        case .upcoming: Color.white.opacity(0.04)
        }
    }

    private var circleStroke: Color {
        state == .upcoming ? Color.white.opacity(0.22) : Color.clear
    }
}

private struct StepConnector: View {
    let complete: Bool

    var body: some View {
        Rectangle()
            .fill(complete ? Brand.purple.opacity(0.65) : Color.white.opacity(0.18))
            .frame(width: 1, height: 36)
            .padding(.leading, 17)
    }
}

private struct WelcomeView: View {
    @EnvironmentObject private var model: AppModel
    @State private var isTargeted = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                Text("Check your app for")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                Text("common security mistakes.")
                    .font(.system(size: 40, weight: .bold, design: .rounded))
                    .foregroundStyle(Brand.lilac)
                    .padding(.bottom, 22)

                Text("Prefunk gives your coding agent a local security preflight—all on your Mac.")
                    .font(.system(size: 16))
                    .foregroundStyle(Brand.muted)
                    .frame(maxWidth: 650, alignment: .leading)
                    .padding(.bottom, 40)

                DropZone(isTargeted: $isTargeted)

                HStack(spacing: 14) {
                    Rectangle().fill(Brand.border).frame(height: 1)
                    Text("or")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Brand.muted)
                    Rectangle().fill(Brand.border).frame(height: 1)
                }
                .padding(.vertical, 24)

                Button(action: model.chooseAndScanFolder) {
                    HStack(spacing: 10) {
                        if model.isScanning {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: "folder")
                        }
                        Text(model.isScanning ? "Checking your project…" : "Choose a project")
                            .font(.system(size: 16, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 52)
                }
                .buttonStyle(PurpleButtonStyle())
                .frame(width: 380)
                .frame(maxWidth: .infinity)
                .disabled(model.isScanning)

                Text("Works with apps, websites, and backends.")
                    .font(.system(size: 13))
                    .foregroundStyle(Brand.muted)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 18)
            }
            .frame(maxWidth: 760)
            .padding(.horizontal, 72)
            .padding(.vertical, 70)
        }
    }
}

private struct DropZone: View {
    @EnvironmentObject private var model: AppModel
    @Binding var isTargeted: Bool

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: isTargeted ? "folder.fill.badge.plus" : "folder.fill")
                .font(.system(size: 58, weight: .medium))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(Brand.lilac)

            Text(isTargeted ? "Drop it here" : "Drag & drop your project folder here")
                .font(.system(size: 20, weight: .semibold, design: .rounded))

            Text("We’ll scan readable files in this folder and its subfolders.")
                .font(.system(size: 14))
                .foregroundStyle(Brand.muted)

            Label("Nothing is uploaded or run.", systemImage: "lock.fill")
                .font(.system(size: 13, weight: .medium))
                .padding(.horizontal, 14)
                .padding(.vertical, 9)
                .background(Brand.surfaceStrong, in: RoundedRectangle(cornerRadius: 8))
                .padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .frame(height: 275)
        .background(isTargeted ? Brand.purple.opacity(0.13) : Brand.surface)
        .overlay {
            RoundedRectangle(cornerRadius: 18)
                .stroke(
                    isTargeted ? Brand.lilac : Brand.purple.opacity(0.75),
                    style: StrokeStyle(lineWidth: isTargeted ? 2 : 1.4, dash: [7, 7])
                )
        }
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first, url.hasDirectoryPath else { return false }
            model.scan(url)
            return true
        } isTargeted: { targeted in
            withAnimation(.easeOut(duration: 0.15)) {
                isTargeted = targeted
            }
        }
    }
}

private struct ResultsView: View {
    @EnvironmentObject private var model: AppModel
    let summary: ScanSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(summary.findings.isEmpty ? "No matches in \(summary.filesScanned) scanned files" : resultHeading)
                        .font(.system(size: 31, weight: .bold, design: .rounded))
                    Text(summary.findings.isEmpty
                         ? "The scanner did not match any of its current rules."
                         : "We’ll walk you through each one.")
                        .font(.system(size: 15))
                        .foregroundStyle(Brand.muted)
                }
                Spacer()
                Button(action: { model.scan(summary.rootURL) }) {
                    Label(model.isScanning ? "Scanning…" : "Scan again", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.borderedProminent)
                .tint(Brand.purple)
                .disabled(model.isScanning)
                Button(action: model.copyAgentPreflight) {
                    Label(model.copiedAgentReport ? "Copied" : "Copy for Codex",
                          systemImage: model.copiedAgentReport ? "checkmark" : "sparkles")
                }
                .buttonStyle(.borderedProminent)
                .tint(Brand.purple)
                Button(action: model.exportAgentJSON) {
                    Label("Agent JSON", systemImage: "curlybraces")
                }
                .buttonStyle(.bordered)
                Button(action: model.exportReport) {
                    Label("Export report", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.bordered)
            }

            if summary.coverage.hasGaps {
                CoverageNotice(coverage: summary.coverage)
            }

            if summary.findings.isEmpty {
                EmptyResultsView()
            } else {
                HStack(alignment: .top, spacing: 22) {
                    findingsList
                        .frame(width: 310)
                    if let finding = model.selectedFinding {
                        FindingDetail(finding: finding)
                    }
                }
            }

            HStack {
                Label("Everything stayed on your Mac", systemImage: "lock.fill")
                Spacer()
                Button("Export report", action: model.exportReport)
                    .buttonStyle(.plain)
                    .foregroundStyle(Brand.lilac)
            }
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(Brand.muted)
        }
        .padding(40)
    }

    private var resultHeading: String {
        let count = summary.findings.count
        return "We found \(count) \(count == 1 ? "thing" : "things") to review"
    }

    private var findingsList: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("FIX FIRST")
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(Brand.lilac)
                .padding(.horizontal, 16)
                .padding(.vertical, 14)

            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(summary.findings) { finding in
                        Button {
                            model.selectedFinding = finding
                        } label: {
                            FindingRow(
                                finding: finding,
                                selected: model.selectedFinding == finding
                            )
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(
                            "\(finding.title), \(finding.severity.label) priority, \(finding.locationSummary)"
                        )
                        .accessibilityHint("Shows details for this finding")
                    }
                }
            }
        }
        .background(Brand.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14).stroke(Brand.border)
        }
    }
}

private struct FindingRow: View {
    let finding: Finding
    let selected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .frame(width: 32, height: 32)
                .background(severityColor.opacity(0.13), in: Circle())
                .foregroundStyle(severityColor)

            VStack(alignment: .leading, spacing: 4) {
                Text(finding.title)
                    .font(.system(size: 14, weight: .semibold))
                    .lineLimit(2)
                Text(finding.locationSummary)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Brand.muted)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(Brand.muted)
        }
        .padding(14)
        .background(selected ? Brand.purple.opacity(0.14) : Color.clear)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Brand.border).frame(height: 1)
        }
    }

    private var severityColor: Color {
        switch finding.severity {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .blue
        }
    }

    private var icon: String {
        finding.ruleID.contains("key") || finding.ruleID.contains("secret") ? "key.fill" : "exclamationmark.shield.fill"
    }
}

private struct FindingDetail: View {
    @EnvironmentObject private var model: AppModel
    let finding: Finding

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: "key.fill")
                        .font(.system(size: 28))
                        .foregroundStyle(.red)
                        .frame(width: 58, height: 58)
                        .background(Color.red.opacity(0.12), in: Circle())

                    VStack(alignment: .leading, spacing: 7) {
                        Text(finding.title)
                            .font(.system(size: 25, weight: .bold, design: .rounded))
                        Text(finding.locationSummary)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(Brand.muted)
                    }
                }
                .padding(.bottom, 28)

                DetailSection(
                    icon: "magnifyingglass",
                    title: "What we found",
                    text: "Prefunk matched this pattern in \(finding.locations.count) \(finding.locations.count == 1 ? "location" : "locations")."
                )
                if finding.locations.count > 1 {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(finding.locations.prefix(8).enumerated()), id: \.offset) { _, location in
                            Text(location.display)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(Brand.muted)
                        }
                        if finding.locations.count > 8 {
                            Text("+ \(finding.locations.count - 8) more in the exported report")
                                .font(.system(size: 11))
                                .foregroundStyle(Brand.muted)
                        }
                    }
                    .padding(.bottom, 18)
                }
                DetailSection(
                    icon: "shield.fill",
                    title: "Why it matters",
                    text: finding.explanation
                )
                DetailSection(
                    icon: "checkmark.circle",
                    title: "How to fix it",
                    text: finding.remediation,
                    showDivider: false
                )

                Button {
                    model.copyFixPrompt(for: finding)
                } label: {
                    Label(
                        model.copiedFindingID == finding.id
                            ? "Copied — paste into Codex"
                            : "Copy guided fix",
                        systemImage: model.copiedFindingID == finding.id
                            ? "checkmark"
                            : "doc.on.doc"
                    )
                        .font(.system(size: 15, weight: .semibold))
                        .padding(.horizontal, 8)
                        .frame(height: 44)
                }
                .buttonStyle(PurpleButtonStyle())
                .accessibilityHint("Copies a redacted review-and-fix prompt")

                Text("Paste this into Codex or another coding assistant. It will verify the issue before changing anything.")
                    .font(.system(size: 12))
                    .foregroundStyle(Brand.muted)
                    .padding(.top, 10)
            }
            .padding(30)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Brand.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14).stroke(Brand.border)
        }
    }
}

private struct DetailSection: View {
    let icon: String
    let title: String
    let text: String
    var showDivider = true

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(Brand.lilac)
            Text(text)
                .font(.system(size: 14))
                .foregroundStyle(.white.opacity(0.86))
                .lineSpacing(4)
                .textSelection(.enabled)
            if showDivider {
                Rectangle().fill(Brand.border).frame(height: 1).padding(.vertical, 12)
            }
        }
        .padding(.bottom, showDivider ? 0 : 24)
    }
}

private struct EmptyResultsView: View {
    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 70))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.green)
            Text("No configured patterns were detected.")
                .font(.system(size: 18, weight: .semibold))
            Text("This is not proof that the app is secure. Review the coverage above and test authentication, authorization, and server behavior separately.")
                .font(.system(size: 14))
                .foregroundStyle(Brand.muted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct CoverageNotice: View {
    let coverage: ScanCoverage

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 4) {
                Text("Some project content was not inspected")
                    .font(.system(size: 14, weight: .semibold))
                Text(details)
                    .font(.system(size: 12))
                    .foregroundStyle(Brand.muted)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.yellow.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).stroke(Color.yellow.opacity(0.25)) }
    }

    private var details: String {
        var parts: [String] = []
        if coverage.unsupported > 0 { parts.append("\(coverage.unsupported) unsupported files") }
        if coverage.oversized > 0 { parts.append("\(coverage.oversized) oversized files") }
        let inaccessible = coverage.unreadable + coverage.decodeFailures
        if inaccessible > 0 { parts.append("\(inaccessible) unreadable or non-text files") }
        if coverage.excludedDirectoryRoots > 0 { parts.append("\(coverage.excludedDirectoryRoots) excluded directory roots") }
        if coverage.traversalErrors > 0 { parts.append("\(coverage.traversalErrors) folder traversal errors") }
        if coverage.workLimitReached { parts.append("scan work limit reached") }
        if coverage.enumerationFailed { parts.append("folder enumeration failed") }
        return parts.joined(separator: " • ")
    }
}

private struct PurpleButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(.white)
            .background(
                configuration.isPressed ? Brand.purple.opacity(0.78) : Brand.purple,
                in: RoundedRectangle(cornerRadius: 10)
            )
            .scaleEffect(configuration.isPressed ? 0.99 : 1)
    }
}
