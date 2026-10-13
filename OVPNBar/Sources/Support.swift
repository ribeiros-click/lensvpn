import AppKit
import Foundation
import Security
import UniformTypeIdentifiers

// MARK: - Keychain

enum Keychain {
    static let service = "OVPNBar"

    static func get(_ account: String) -> String? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func set(_ value: String, for account: String) {
        delete(account)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrLabel as String: "OVPNBar VPN",
            kSecValueData as String: Data(value.utf8),
        ]
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete(_ account: String) {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(q as CFDictionary)
    }
}

// MARK: - Componente privilegiado (motor + regra sudo)

enum Helper {
    enum State { case ready, outdated, missing }
    struct Cancelled: Error {}
    struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    static let dir = "/usr/local/libexec/ovpnbar"
    static let enginePath = dir + "/ovpnc.py"
    static let sudoersPath = "/etc/sudoers.d/ovpnbar"
    static let python = "/usr/bin/python3"

    static var bundledEngine: URL? { Bundle.main.url(forResource: "ovpnc", withExtension: "py") }

    static func state() -> State {
        guard FileManager.default.fileExists(atPath: enginePath) else { return .missing }
        guard run("/usr/bin/sudo", ["-n", "-l", python, enginePath, "--json"]) == 0 else { return .missing }
        if let b = bundledEngine, let a = try? Data(contentsOf: b),
           let c = try? Data(contentsOf: URL(fileURLWithPath: enginePath)), a == c {
            return .ready
        }
        return .outdated
    }

    static func install() throws {
        guard let src = bundledEngine?.path else { throw Failure(message: "ovpnc.py não encontrado no app") }
        let rule = "\(NSUserName()) ALL=(root) NOPASSWD: \(python) \(enginePath) *"
        let cmds = [
            "set -e",
            "install -d -o root -g wheel -m 755 \(dir)",
            "install -o root -g wheel -m 644 \(q(src)) \(enginePath)",
            "T=$(mktemp /tmp/ovpnbar.XXXXXX)",
            "printf '%s\\n' \(q(rule)) > \"$T\"",
            "/usr/sbin/visudo -cf \"$T\" >/dev/null",
            "install -o root -g wheel -m 440 \"$T\" \(sudoersPath)",
            "rm -f \"$T\"",
        ]
        try runAsAdmin(cmds.joined(separator: "; "),
                       prompt: "O OVPNBar precisa instalar o motor de VPN para criar interfaces de rede.")
    }

    static func uninstall() throws {
        try runAsAdmin("rm -f \(sudoersPath); rm -rf \(dir)",
                       prompt: "O OVPNBar vai remover o motor de VPN instalado.")
    }

    private static func q(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func runAsAdmin(_ sh: String, prompt: String) throws {
        func esc(_ s: String) -> String {
            s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        }
        let src = "do shell script \"\(esc(sh))\" with administrator privileges with prompt \"\(esc(prompt))\""
        var err: NSDictionary?
        NSAppleScript(source: src)?.executeAndReturnError(&err)
        if let err {
            if (err[NSAppleScript.errorNumber] as? Int) == -128 { throw Cancelled() }
            throw Failure(message: err[NSAppleScript.errorMessage] as? String ?? "erro desconhecido")
        }
    }

    @discardableResult
    static func run(_ exe: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe)
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }
}

// MARK: - Arquivos .ovpn

enum OVPNFile {
    static let type = UTType(filenameExtension: "ovpn") ?? .data

    struct Info {
        var remote: String
        var needsAuth: Bool
        var suggestedName: String?
    }

    struct InvalidFile: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Lê um .ovpn e embute (inline) certificados/chaves referenciados por arquivo,
    /// para que o perfil importado (e exportado) seja autocontido.
    static func selfContained(contentsOf url: URL) throws -> String {
        let text = try String(contentsOf: url, encoding: .utf8)
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        let base = url.deletingLastPathComponent()
        let fileTags: Set<String> = ["ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs"]
        var out: [String] = []
        var keyDirection: String?
        var inBlock = false
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("<"), !line.hasPrefix("</") { inBlock = true }
            if line.hasPrefix("</") { inBlock = false }
            let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            if !inBlock, let d = parts.first, fileTags.contains(d), parts.count >= 2, parts[1] != "[inline]" {
                let path = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                let fileURL = path.hasPrefix("/") ? URL(fileURLWithPath: path) : base.appendingPathComponent(path)
                guard let content = try? String(contentsOf: fileURL, encoding: .utf8) else {
                    throw InvalidFile(message: "arquivo referenciado não encontrado: \(path)")
                }
                out += ["<\(d)>", content.trimmingCharacters(in: .newlines), "</\(d)>"]
                if d == "tls-auth", parts.count >= 3 { keyDirection = parts[2] }
                continue
            }
            out.append(raw)
        }
        if let kd = keyDirection, !out.contains(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("key-direction") }) {
            out.append("key-direction \(kd)")
        }
        return out.joined(separator: "\n")
    }

    static func inspect(_ text: String) throws -> Info {
        var remote: String?
        var auth = false
        var name: String?
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            let parts = line.split(separator: " ").map(String.init)
            guard let d = parts.first else { continue }
            if d == "remote", parts.count >= 2, remote == nil {
                remote = parts.count >= 3 ? "\(parts[1]):\(parts[2])" : parts[1]
                if parts.count >= 4, parts[3].hasPrefix("tcp") {
                    throw InvalidFile(message: "conexões TCP não são suportadas (apenas UDP)")
                }
            }
            if d == "proto", parts.count >= 2, parts[1].hasPrefix("tcp") {
                throw InvalidFile(message: "conexões TCP não são suportadas (apenas UDP)")
            }
            if d == "auth-user-pass" { auth = true }
            if line.hasPrefix("#viscosity name ") { name = String(line.dropFirst("#viscosity name ".count)) }
        }
        guard let remote else { throw InvalidFile(message: "não parece um arquivo OpenVPN (sem \"remote\")") }
        guard text.contains("<ca>") || text.contains("\nca ") else {
            throw InvalidFile(message: "certificado da CA ausente")
        }
        return Info(remote: remote, needsAuth: auth, suggestedName: name)
    }

    /// Grava com permissão 0600 (o arquivo contém a chave privada).
    static func writePrivate(_ text: String, to url: URL) throws {
        try Data(text.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static func safeFileName(_ name: String) -> String {
        let bad = CharacterSet(charactersIn: "/:\\")
        return name.components(separatedBy: bad).joined(separator: "-")
    }
}

// MARK: - Diálogos

@MainActor
enum Dialogs {
    static func error(_ title: String, _ message: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = title
        a.informativeText = message
        a.runModal()
    }

    static func confirm(_ title: String, _ message: String, ok: String, destructive: Bool = false) -> Bool {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        let b = a.addButton(withTitle: ok)
        b.hasDestructiveAction = destructive
        a.addButton(withTitle: "Cancelar")
        return a.runModal() == .alertFirstButtonReturn
    }

    static func prompt(_ title: String, _ message: String, value: String, placeholder: String = "") -> String? {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.informativeText = message
        a.addButton(withTitle: "OK")
        a.addButton(withTitle: "Cancelar")
        let f = NSTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
        f.stringValue = value
        f.placeholderString = placeholder
        a.accessoryView = f
        a.window.initialFirstResponder = f
        return a.runModal() == .alertFirstButtonReturn ? f.stringValue : nil
    }

    struct Credentials {
        var user: String
        var password: String
        var remember: Bool
    }

    static func credentials(profile: String, user: String) -> Credentials? {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Credenciais — \(profile)"
        a.informativeText = "Informe o usuário e a senha da VPN."
        a.addButton(withTitle: "Conectar")
        a.addButton(withTitle: "Cancelar")

        let u = NSTextField(frame: NSRect(x: 0, y: 60, width: 280, height: 24))
        u.placeholderString = "Usuário"
        u.stringValue = user
        let p = NSSecureTextField(frame: NSRect(x: 0, y: 30, width: 280, height: 24))
        p.placeholderString = "Senha"
        let r = NSButton(checkboxWithTitle: "Lembrar senha no Keychain", target: nil, action: nil)
        r.frame = NSRect(x: 0, y: 0, width: 280, height: 22)
        r.state = .on
        let box = NSView(frame: NSRect(x: 0, y: 0, width: 280, height: 86))
        [u, p, r].forEach(box.addSubview)
        u.nextKeyView = p
        a.accessoryView = box
        a.window.initialFirstResponder = user.isEmpty ? u : p

        guard a.runModal() == .alertFirstButtonReturn else { return nil }
        let name = u.stringValue.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty else { return nil }
        return Credentials(user: name, password: p.stringValue, remember: r.state == .on)
    }
}
