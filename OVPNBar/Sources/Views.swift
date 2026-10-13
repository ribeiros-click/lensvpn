import AppKit
import SwiftUI

struct MenuIcon: View {
    @ObservedObject var model: AppModel

    var body: some View {
        let n = model.connectedCount
        HStack(spacing: 2) {
            Image(systemName: model.iconName)
            if n > 1 { Text("\(n)") }
        }
    }
}

struct MenuContent: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "lock.shield.fill").foregroundStyle(.tint)
                Text("OVPNBar").font(.headline)
                Spacer()
                Text(summary).font(.caption).foregroundStyle(.secondary)
            }

            if model.helper != .ready { HelperBanner() }

            if model.profiles.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "tray").font(.title2).foregroundStyle(.secondary)
                    Text("Nenhuma conexão").font(.callout)
                    Text("Importe um arquivo .ovpn para começar.").font(.caption).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
            } else {
                VStack(spacing: 2) {
                    ForEach(model.profiles) { p in
                        ProfileRow(profile: p, status: model.status[p.id] ?? ConnStatus())
                    }
                }
            }

            Divider()

            HStack(spacing: 8) {
                Button { model.importWithPanel() } label: {
                    Label("Importar…", systemImage: "square.and.arrow.down")
                }
                Button { model.exportAll() } label: {
                    Label("Exportar…", systemImage: "square.and.arrow.up")
                }
                .disabled(model.profiles.isEmpty)
                Spacer()
                SettingsMenu()
            }
            .controlSize(.small)
        }
        .padding(12)
        .frame(width: 380)
    }

    private var summary: String {
        let n = model.connectedCount
        return n == 0 ? "desconectado" : (n == 1 ? "1 conectada" : "\(n) conectadas")
    }
}

struct HelperBanner: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.helper == .missing ? "Motor de VPN não instalado" : "Motor de VPN desatualizado")
                    .font(.callout).fontWeight(.medium)
                Text("Necessário para criar interfaces de rede. Pede a senha de administrador uma vez.")
                    .font(.caption).foregroundStyle(.secondary)
                Button(model.helper == .missing ? "Instalar…" : "Atualizar…") { model.installHelper() }
                    .controlSize(.small)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color.orange.opacity(0.12)))
    }
}

struct ProfileRow: View {
    @EnvironmentObject var model: AppModel
    let profile: Profile
    let status: ConnStatus
    @State private var hover = false

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(dotColor).frame(width: 9, height: 9)
            VStack(alignment: .leading, spacing: 2) {
                Text(profile.name).fontWeight(.medium).lineLimit(1)
                Text(subtitle).font(.caption).foregroundStyle(status.lastError != nil && status.phase == .disconnected ? .red : .secondary)
                    .lineLimit(1).truncationMode(.tail)
            }
            Spacer(minLength: 4)
            Toggle("", isOn: Binding(
                get: { status.phase != .disconnected },
                set: { model.toggle(profile, on: $0) }))
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.small)
                .disabled(status.phase == .disconnecting)
            Menu {
                Button("Ver log…") { LogWindows.show(profile: profile, buffer: model.log(for: profile.id)) }
                Divider()
                Button("Credenciais…") { model.editCredentials(profile) }
                if model.hasSavedPassword(profile) {
                    Button("Esquecer senha salva") { model.forgetPassword(profile) }
                }
                Button("Domínios DNS…") { model.editDNS(profile) }
                Button("Renomear…") { model.rename(profile) }
                Divider()
                Button("Exportar .ovpn…") { model.export(profile) }
                Button("Mostrar no Finder") { model.revealInFinder(profile) }
                Divider()
                Button("Remover…", role: .destructive) { model.remove(profile) }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(hover ? Color.primary.opacity(0.06) : .clear))
        .onHover { hover = $0 }
    }

    private var dotColor: Color {
        switch status.phase {
        case .connected: return .green
        case .starting, .connecting, .authenticating, .reconnecting: return .orange
        case .disconnecting: return .gray
        case .disconnected: return status.lastError != nil ? .red : .gray.opacity(0.5)
        }
    }

    private var subtitle: String {
        switch status.phase {
        case .starting: return "Iniciando…"
        case .connecting: return "Conectando a \(profile.remote)…"
        case .authenticating: return "Autenticando…"
        case .reconnecting: return "Reconectando…"
        case .disconnecting: return "Desconectando…"
        case .connected:
            let f = ByteCountFormatter()
            f.countStyle = .file
            var parts = [status.ip ?? "?"]
            if let i = status.ifname { parts.append(i) }
            parts.append("↓\(f.string(fromByteCount: status.bytesIn)) ↑\(f.string(fromByteCount: status.bytesOut))")
            return parts.joined(separator: " · ")
        case .disconnected:
            return status.lastError ?? profile.remote
        }
    }
}

struct SettingsMenu: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        Menu {
            Toggle("Abrir ao iniciar sessão", isOn: Binding(
                get: { model.launchAtLogin },
                set: { model.launchAtLogin = $0 }))
            Divider()
            Button("Desconectar todas") { model.disconnectAll() }
                .disabled(model.status.values.allSatisfy { $0.phase == .disconnected })
            Button("Abrir pasta de perfis") { NSWorkspace.shared.open(model.profilesDir) }
            Divider()
            Button("Reinstalar motor de VPN…") { model.installHelper() }
            Button("Remover motor de VPN…") { model.uninstallHelper() }
                .disabled(model.helper == .missing)
            Divider()
            Button("Sair do OVPNBar") { NSApp.terminate(nil) }
        } label: {
            Image(systemName: "gearshape")
        }
        .menuStyle(.borderlessButton)
        .menuIndicator(.hidden)
        .fixedSize()
    }
}

// MARK: - Janela de log

struct LogView: View {
    @ObservedObject var buffer: LogBuffer

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(buffer.lines.enumerated()), id: \.offset) { i, line in
                            Text(line)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(color(line))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(i)
                        }
                    }
                    .padding(10)
                }
                .onChange(of: buffer.lines.count) { _, n in
                    if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) }
                }
                .onAppear {
                    if !buffer.lines.isEmpty { proxy.scrollTo(buffer.lines.count - 1, anchor: .bottom) }
                }
            }
            Divider()
            HStack {
                Text("\(buffer.lines.count) linhas").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Copiar") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(buffer.lines.joined(separator: "\n"), forType: .string)
                }
                Button("Limpar") { buffer.clear() }
            }
            .controlSize(.small)
            .padding(8)
        }
        .frame(minWidth: 560, minHeight: 320)
    }

    private func color(_ line: String) -> Color {
        if line.contains(" E ") { return .red }
        if line.contains(" W ") { return .orange }
        if line.contains("CONECTADO") { return .green }
        return .primary
    }
}

@MainActor
enum LogWindows {
    private static var windows: [UUID: NSWindow] = [:]

    static func show(profile: Profile, buffer: LogBuffer) {
        NSApp.activate(ignoringOtherApps: true)
        if let w = windows[profile.id] {
            w.makeKeyAndOrderFront(nil)
            return
        }
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 420),
                         styleMask: [.titled, .closable, .resizable, .miniaturizable],
                         backing: .buffered, defer: false)
        w.title = "Log — \(profile.name)"
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: LogView(buffer: buffer))
        w.center()
        w.makeKeyAndOrderFront(nil)
        windows[profile.id] = w
    }
}
