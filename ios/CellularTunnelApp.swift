import SwiftUI
import UniformTypeIdentifiers
import UIKit

@MainActor
final class TunnelModel: ObservableObject {
    @Published var importing = false
    @Published var status = "Importa el archivo privado iphone-pairing.json generado en tu Mac." {
        didSet {
            print("[CellularTunnel] " + status)
            fflush(stdout)
            let diagnostic = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("tunnel-status.txt")
            try? Data(status.utf8).write(to: diagnostic, options: .atomic)
        }
    }
    @Published var sessionCount = 0
    @Published var loaded = false
    @Published var running = false
    @Published var fingerprint = ""
    private var package: PairingPackage?
    private var server: TunnelServer?

    func load(url: URL) {
        stop()
        package = nil; loaded = false; fingerprint = ""
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let resource = try url.resourceValues(forKeys: [.fileSizeKey])
            guard (resource.fileSize ?? Int.max) <= 131_072 else { throw TunnelError.invalidPairing }
            let data = try Data(contentsOf: url)
            let decoded = try JSONDecoder().decode(PairingPackage.self, from: data)
            _ = try decoded.identity()
            package = decoded; loaded = true
            fingerprint = decoded.certificate_sha256
            status = "Emparejamiento cargado solo en memoria. Pulsa Iniciar."
        } catch { status = "No se pudo importar el archivo de emparejamiento. Error: \(error.localizedDescription)" }
    }

    func loadUSB() {
        var url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("iphone-pairing.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            status = "No hay emparejamiento USB transferido todavía."; return
        }
        do {
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            var values = URLResourceValues(); values.isExcludedFromBackup = true
            try url.setResourceValues(values)
            load(url: url)
        } catch { status = "No se pudo proteger el archivo USB." }
    }

    func start() {
        guard let package = package, !running else { return }
        do {
            let host = TunnelServer()
            host.onStatus = { [weak self, weak host] text, count in
                guard let self = self, self.server === host else { return }
                self.status = text; self.sessionCount = count
            }
            host.onFailure = { [weak self, weak host] in
                guard let self = self, self.server === host else { return }
                self.stop()
                self.status = "El servidor falló. Puedes volver a Iniciar."
            }
            try host.start(package: package)
            server = host; running = true
            UIApplication.shared.isIdleTimerDisabled = true
            status = "Iniciando servidor cifrado…"
        } catch { status = "No se pudo iniciar. Revisa firma y emparejamiento." }
    }

    func stop() {
        server?.stop(); server = nil
        sessionCount = 0; running = false
        UIApplication.shared.isIdleTimerDisabled = false
        status = "Detenido. Ninguna sesión activa."
    }

    func forget() { stop(); package = nil; loaded = false; fingerprint = "" }
}

@main
struct CellularTunnelApp: App {
    @StateObject private var model = TunnelModel()
    @Environment(\.scenePhase) private var phase
    var body: some Scene {
        WindowGroup {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Puente celular").font(.largeTitle.bold())
                    Text("Prototipo privado para tu Mac. Solo salida celular; se detiene al salir de esta app.")
                    Text(model.status).accessibilityLabel("Estado: \(model.status)")
                    Text("Sesiones activas: \(model.sessionCount) / \(Wire.maxSessions)")
                    Button("Importar emparejamiento privado") { model.importing = true }.disabled(model.running)
                    Button("Cargar emparejamiento USB") { model.loadUSB() }.disabled(model.running)
                    if model.loaded {
                        Text("Huella del certificado:").font(.headline)
                        Text(model.fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        Button("Iniciar") { model.start() }.disabled(model.running)
                        Button("Detener") { model.stop() }.disabled(!model.running)
                        Button("Olvidar emparejamiento") { model.forget() }
                    }
                    Text("No modifica tu plan ni garantiza evitar la cuota del operador. No captura por sí solo todo el tráfico del Mac. Mantén el iPhone conectado a corriente.")
                        .font(.footnote)
                }.padding()
            }
            .fileImporter(isPresented: $model.importing, allowedContentTypes: [.json]) { result in
                switch result {
                case .success(let url): model.load(url: url)
                case .failure: model.status = "Importación cancelada o no disponible."
                }
            }
            .onAppear {
                // Explicit development launch argument, not automatic on every launch.
                if ProcessInfo.processInfo.arguments.contains("--start-usb") {
                    model.loadUSB()
                    // Keep this explicit diagnostic session visible even if import fails.
                    // Leaving the app calls stop() and restores normal idle behavior.
                    UIApplication.shared.isIdleTimerDisabled = true
                    if model.loaded { model.start() }
                }
            }
            .onChange(of: phase) { value in
                if value == .background { model.stop() }
            }
        }
    }
}
