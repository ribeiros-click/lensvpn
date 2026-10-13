import AppKit
import Foundation
import ServiceManagement

struct Profile: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var remote: String
    var needsAuth: Bool
    var username: String = ""
    var dnsDomains: [String] = []
}

enum Phase {
    case disconnected, starting, connecting, authenticating, connected, reconnecting, disconnecting
}

struct ConnStatus {
    var phase: Phase = .disconnected
    var ip: String?
    var ifname: String?
    var cipher: String?
    var bytesIn: Int64 = 0
    var bytesOut: Int64 = 0
    var since: Date?
    var lastError: String?
}

@MainActor
final class LogBuffer: ObservableObject {
    @Published private(set) var lines: [String] = []
    private static let fmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    func append(_ line: String) {
        lines.append(line)
        if lines.count > 3000 { lines.removeFirst(lines.count - 3000) }
    }

    func note(_ msg: String) { append("\(Self.fmt.string(from: Date())) · \(msg)") }
    func clear() { lines.removeAll() }
}

@MainActor
final class Runner {
    let process = Process()
    let stdinPipe = Pipe()
    let stdoutPipe = Pipe()
    let stderrPipe = Pipe()
    var outBuf = Data()
    var errBuf = Data()
    var errText = ""
    var userStopped = false
}

@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    @Published var profiles: [Profile] = []
    @Published var status: [UUID: ConnStatus] = [:]
    @Published var helper: Helper.State = .missing

    private var runners: [UUID: Runner] = [:]
    private var logs: [UUID: LogBuffer] = [:]
    private var quitting = false

    let baseDir: URL
    let profilesDir: URL
    private let indexURL: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        baseDir = support.appendingPathComponent("OVPNBar", isDirectory: true)
        profilesDir = baseDir.appendingPathComponent("profiles", isDirectory: true)
        indexURL = baseDir.appendingPathComponent("profiles.json")
        try? FileManager.default.createDirectory(at: profilesDir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        load()
        refreshHelper()
    }

    // MARK: estado agregado

    var connectedCount: Int { status.values.filter { $0.phase == .connected }.count }
    var busy: Bool { status.values.contains { [.starting, .connecting, .authenticating, .reconnecting].contains($0.phase) } }

    var iconName: String {
        if connectedCount > 0 { return "lock.shield.fill" }
        if busy { return "shield.lefthalf.filled" }
        return "shield"
    }

    func log(for id: UUID) -> LogBuffer {
        if let l = logs[id] { return l }
        let l = LogBuffer()
        logs[id] = l
        return l
    }

    func configURL(_ p: Profile) -> URL { profilesDir.appendingPathComponent("\(p.id.uuidString).ovpn") }

    // MARK: persistência

    private func load() {
        guard let data = try? Data(contentsOf: indexURL),
              let list = try? JSONDecoder().decode([Profile].self, from: data) else { return }
        profiles = list.filter { FileManager.default.fileExists(atPath: configURL($0).path) }
    }

    private func save() {
        let enc = JSONEncoder()
        enc.outputFormatting = .prettyPrinted
        if let data = try? enc.encode(profiles) { try? data.write(to: indexURL, options: .atomic) }
    }

    private func update(_ id: UUID, _ change: (inout Profile) -> Void) {
        guard let i = profiles.firstIndex(where: { $0.id == id }) else { return }
        change(&profiles[i])
        save()
    }

    // MARK: componente privilegiado

    func refreshHelper() { helper = Helper.state() }

    func installHelper() {
        do {
            try Helper.install()
            refreshHelper()
            if helper == .missing {
                Dialogs.error("Instalação incompleta",
                              "O motor foi copiado, mas o sudo não liberou o comando. Verifique se /etc/sudoers inclui /etc/sudoers.d.")
            }
        } catch is Helper.Cancelled {
        } catch {
            Dialogs.error("Falha ao instalar", error.localizedDescription)
        }
    }

    func uninstallHelper() {
        guard runners.isEmpty else {
            Dialogs.error("Conexões ativas", "Desconecte todas as VPNs antes de remover o motor.")
            return
        }
        do { try Helper.uninstall() } catch is Helper.Cancelled {} catch {
            Dialogs.error("Falha ao remover", error.localizedDescription)
        }
        refreshHelper()
    }

    // MARK: importação / exportação

    func importWithPanel() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "Importar configuração OpenVPN"
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = [OVPNFile.type]
        if panel.runModal() == .OK { importURLs(panel.urls) }
    }

    func importURLs(_ urls: [URL]) {
        var errors: [String] = []
        var imported: [String] = []
        for url in urls {
            do { imported.append(try importOne(url)) } catch {
                errors.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        if !errors.isEmpty {
            Dialogs.error("Falha ao importar", errors.joined(separator: "\n"))
        }
    }

    private func importOne(_ url: URL) throws -> String {
        let text = try OVPNFile.selfContained(contentsOf: url)
        let info = try OVPNFile.inspect(text)
        let base = url.deletingPathExtension().lastPathComponent
        let p = Profile(name: uniqueName(base), remote: info.remote, needsAuth: info.needsAuth)
        try OVPNFile.writePrivate(text, to: configURL(p))
        profiles.append(p)
        save()
        log(for: p.id).note("perfil importado de \(url.path)")
        return p.name
    }

    private func uniqueName(_ base: String) -> String {
        var name = base
        var n = 2
        while profiles.contains(where: { $0.name == name }) {
            name = "\(base) \(n)"
            n += 1
        }
        return name
    }

    func export(_ p: Profile) {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSSavePanel()
        panel.title = "Exportar \(p.name)"
        panel.nameFieldStringValue = OVPNFile.safeFileName(p.name) + ".ovpn"
        panel.allowedContentTypes = [OVPNFile.type]
        guard panel.runModal() == .OK, let dest = panel.url else { return }
        do {
            try OVPNFile.writePrivate(try String(contentsOf: configURL(p), encoding: .utf8), to: dest)
        } catch {
            Dialogs.error("Falha ao exportar", error.localizedDescription)
        }
    }

    func exportAll() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "Exportar todas as conexões"
        panel.prompt = "Exportar"
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let dir = panel.url else { return }
        var written: [URL] = []
        do {
            for p in profiles {
                var dest = dir.appendingPathComponent(OVPNFile.safeFileName(p.name) + ".ovpn")
                var n = 2
                while FileManager.default.fileExists(atPath: dest.path) {
                    dest = dir.appendingPathComponent("\(OVPNFile.safeFileName(p.name)) \(n).ovpn")
                    n += 1
                }
                try OVPNFile.writePrivate(try String(contentsOf: configURL(p), encoding: .utf8), to: dest)
                written.append(dest)
            }
            NSWorkspace.shared.activateFileViewerSelecting(written)
        } catch {
            Dialogs.error("Falha ao exportar", error.localizedDescription)
        }
    }

    // MARK: edição de perfis

    func rename(_ p: Profile) {
        guard let name = Dialogs.prompt("Renomear conexão", "", value: p.name)?
            .trimmingCharacters(in: .whitespaces), !name.isEmpty else { return }
        update(p.id) { $0.name = name }
    }

    func editCredentials(_ p: Profile) {
        guard let c = Dialogs.credentials(profile: p.name, user: p.username) else { return }
        update(p.id) { $0.username = c.user }
        if c.remember { Keychain.set(c.password, for: p.id.uuidString) } else { Keychain.delete(p.id.uuidString) }
    }

    func forgetPassword(_ p: Profile) { Keychain.delete(p.id.uuidString) }
    func hasSavedPassword(_ p: Profile) -> Bool { Keychain.get(p.id.uuidString) != nil }

    func editDNS(_ p: Profile) {
        guard let v = Dialogs.prompt("Domínios DNS — \(p.name)",
                                     "Domínios resolvidos pelo DNS da VPN, separados por vírgula. Vale na próxima conexão.",
                                     value: p.dnsDomains.joined(separator: ", "),
                                     placeholder: "empresa.local, intranet.corp") else { return }
        let list = v.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        update(p.id) { $0.dnsDomains = list }
    }

    func remove(_ p: Profile) {
        guard Dialogs.confirm("Remover \(p.name)?", "O perfil e a senha salva serão apagados.",
                              ok: "Remover", destructive: true) else { return }
        disconnect(p)
        try? FileManager.default.removeItem(at: configURL(p))
        Keychain.delete(p.id.uuidString)
        profiles.removeAll { $0.id == p.id }
        status[p.id] = nil
        save()
    }

    func revealInFinder(_ p: Profile) {
        NSWorkspace.shared.activateFileViewerSelecting([configURL(p)])
    }

    // MARK: conexão

    func toggle(_ p: Profile, on: Bool) {
        if on { connect(p) } else { disconnect(p) }
    }

    func connect(_ p: Profile) {
        guard runners[p.id] == nil else { return }
        if helper == .missing {
            if Dialogs.confirm("Instalar motor de VPN",
                               "Para criar interfaces de rede o OVPNBar precisa instalar um componente com privilégios de administrador (uma única vez).",
                               ok: "Instalar") {
                installHelper()
            }
            guard helper != .missing else { return }
        }

        var user = p.username
        var pass = ""
        if p.needsAuth {
            if !user.isEmpty, let saved = Keychain.get(p.id.uuidString) {
                pass = saved
            } else {
                guard let c = Dialogs.credentials(profile: p.name, user: user) else { return }
                user = c.user
                pass = c.password
                update(p.id) { $0.username = c.user }
                if c.remember { Keychain.set(c.password, for: p.id.uuidString) }
            }
        }
        start(p, user: user, password: pass)
    }

    private func start(_ p: Profile, user: String, password: String) {
        let id = p.id
        let r = Runner()
        var args = ["-n", Helper.python, Helper.enginePath, "--json", "--auth-stdin", "--watch-stdin"]
        for d in p.dnsDomains { args += ["--dns-domain", d] }
        args.append(configURL(p).path)
        r.process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        r.process.arguments = args
        r.process.standardInput = r.stdinPipe
        r.process.standardOutput = r.stdoutPipe
        r.process.standardError = r.stderrPipe

        r.stdoutPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil }
            Task { @MainActor in AppModel.shared.received(id, d, isErr: false) }
        }
        r.stderrPipe.fileHandleForReading.readabilityHandler = { h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil }
            Task { @MainActor in AppModel.shared.received(id, d, isErr: true) }
        }
        r.process.terminationHandler = { proc in
            let code = proc.terminationStatus
            Task { @MainActor in AppModel.shared.terminated(id, code: code) }
        }

        status[id] = ConnStatus(phase: .starting)
        log(for: id).note("conectando \(p.name) (\(p.remote))")
        do {
            try r.process.run()
        } catch {
            status[id] = ConnStatus(lastError: error.localizedDescription)
            return
        }
        runners[id] = r
        try? r.stdinPipe.fileHandleForWriting.write(contentsOf: Data("\(user)\n\(password)\n".utf8))
    }

    func disconnect(_ p: Profile) {
        guard let r = runners[p.id] else { return }
        r.userStopped = true
        status[p.id]?.phase = .disconnecting
        log(for: p.id).note("desconectando")
        // fechar o stdin faz o motor encerrar limpando rotas e DNS
        try? r.stdinPipe.fileHandleForWriting.close()
        DispatchQueue.main.asyncAfter(deadline: .now() + 8) { [weak r] in
            if let r, r.process.isRunning { r.process.interrupt() }
        }
    }

    func disconnectAll() {
        for p in profiles { disconnect(p) }
    }

    /// Chamado ao sair do app: espera os motores desmontarem a rede.
    func shouldTerminate() -> NSApplication.TerminateReply {
        if runners.isEmpty { return .terminateNow }
        quitting = true
        disconnectAll()
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
            NSApp.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }

    // MARK: saída do motor

    fileprivate func received(_ id: UUID, _ data: Data, isErr: Bool) {
        guard let r = runners[id] else { return }
        var buf = isErr ? r.errBuf : r.outBuf
        buf.append(data)
        if data.isEmpty, !buf.isEmpty { buf.append(0x0A) }
        while let nl = buf.firstIndex(of: 0x0A) {
            let lineData = buf[buf.startIndex..<nl]
            buf.removeSubrange(buf.startIndex...nl)
            guard let line = String(data: lineData, encoding: .utf8), !line.isEmpty else { continue }
            if !isErr, let obj = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any] {
                handleEvent(id, obj)
            } else {
                if isErr { r.errText += line + "\n" }
                log(for: id).append(line)
            }
        }
        if isErr { r.errBuf = buf } else { r.outBuf = buf }
    }

    private func handleEvent(_ id: UUID, _ e: [String: Any]) {
        var st = status[id] ?? ConnStatus()
        switch e["event"] as? String {
        case "state":
            switch e["state"] as? String {
            case "connecting", "tls_ok": st.phase = .connecting
            case "authenticating": st.phase = .authenticating
            case "reconnecting": st.phase = .reconnecting
            case "connected":
                st.phase = .connected
                st.ip = e["ip"] as? String
                st.ifname = e["ifname"] as? String
                st.cipher = e["cipher"] as? String
                st.since = Date()
                st.lastError = nil
            case "disconnected": st.phase = .disconnecting
            default: break
            }
        case "stats":
            st.bytesIn = (e["bytes_in"] as? NSNumber)?.int64Value ?? st.bytesIn
            st.bytesOut = (e["bytes_out"] as? NSNumber)?.int64Value ?? st.bytesOut
        case "error":
            let msg = e["message"] as? String ?? "erro"
            st.lastError = msg
            if (e["auth"] as? Bool) == true {
                Keychain.delete(id.uuidString)
                let name = profiles.first { $0.id == id }?.name ?? "VPN"
                DispatchQueue.main.async {
                    Dialogs.error("Falha de autenticação — \(name)",
                                  "Usuário ou senha recusados pelo servidor. A senha salva foi apagada.")
                }
            }
        default: break
        }
        if runners[id]?.userStopped == true, st.phase != .disconnected { st.phase = .disconnecting }
        status[id] = st
    }

    fileprivate func terminated(_ id: UUID, code: Int32) {
        let r = runners.removeValue(forKey: id)
        var st = status[id] ?? ConnStatus()
        st.phase = .disconnected
        st.ip = nil
        st.ifname = nil
        st.since = nil
        if let r, r.errText.contains("password is required") {
            st.lastError = "motor de VPN não autorizado — reinstale o componente"
            refreshHelper()
        } else if r?.userStopped == true {
            st.lastError = nil
        } else if code != 0, st.lastError == nil {
            st.lastError = "encerrado (código \(code))"
        }
        status[id] = st
        log(for: id).note("processo encerrado (código \(code))")
        if quitting, runners.isEmpty { NSApp.reply(toApplicationShouldTerminate: true) }
    }

    // MARK: iniciar com o sistema

    var launchAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            } catch {
                Dialogs.error("Iniciar com o sistema", error.localizedDescription)
            }
            objectWillChange.send()
        }
    }
}
