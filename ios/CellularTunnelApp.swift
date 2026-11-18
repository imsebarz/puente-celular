import SwiftUI
import UniformTypeIdentifiers
import UIKit
import CoreTransferable

private struct ClientProfile: Transferable {
    let data: Data
    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .json) { $0.data }
            .suggestedFileName("mac-config.json")
    }
}

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
    @Published private(set) var devices: [PairedDevice] = []
    @Published var deviceNotice = ""
    private var package: PairingPackage?
    private var server: TunnelServer?

    func load(url: URL) {
        stop()
        package = nil; loaded = false; fingerprint = ""; devices = []; deviceNotice = ""
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let resource = try url.resourceValues(forKeys: [.fileSizeKey])
            guard (resource.fileSize ?? Int.max) <= 131_072 else { throw TunnelError.invalidPairing }
            let data = try Data(contentsOf: url)
            let decoded = try JSONDecoder().decode(PairingPackage.self, from: data)
            _ = try decoded.identity()
            devices = try DeviceStore(fingerprint: decoded.certificate_sha256).load(initialToken: decoded.token)
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
            try host.start(package: package, devices: devices)
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

    private func commit(_ updated: [PairedDevice]) throws {
        guard let package else { throw DeviceAccessError.missing }
        try DeviceStore(fingerprint: package.certificate_sha256).save(updated)
        server?.updateDevices(updated)
        devices = updated
    }

    func addDevice(name: String, gateway: String) -> Bool {
        do {
            let device = try PairedDevice.issue(name: name, gateway: gateway, among: devices)
            try commit(devices + [device])
            deviceNotice = "Equipo añadido. Comparte su configuración solo con ese equipo."
            return true
        } catch { deviceNotice = error.localizedDescription; return false }
    }

    func revoke(_ device: PairedDevice) {
        do {
            guard devices.contains(where: { $0.id == device.id }) else { throw DeviceAccessError.missing }
            try commit(devices.filter { $0.id != device.id })
            deviceNotice = "Acceso retirado a " + device.name + "."
        } catch { deviceNotice = error.localizedDescription }
    }

    fileprivate func profile(for device: PairedDevice) -> ClientProfile? {
        guard let package, let data = try? device.profile(for: package) else { return nil }
        return ClientProfile(data: data)
    }

    func forget() { stop(); package = nil; loaded = false; fingerprint = ""; devices = []; deviceNotice = "" }
}

private struct DeviceList: View {
    @ObservedObject var model: TunnelModel
    @State private var adding = false
    @State private var name = ""
    @State private var gateway = "172.20.10.1"
    @State private var revoking: PairedDevice?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Equipos autorizados").font(.headline)
            ForEach(model.devices) { device in
                VStack(alignment: .leading, spacing: 8) {
                    Text(device.name).fontWeight(.medium)
                    if let profile = model.profile(for: device) {
                        ShareLink(item: profile, preview: SharePreview("Configuración de " + device.name)) {
                            Label("Compartir configuración", systemImage: "square.and.arrow.up")
                        }.accessibilityLabel("Compartir configuración de " + device.name)
                    } else {
                        Text("Incluye a quienes tengan una copia del archivo inicial.").font(.footnote)
                    }
                    Button("Quitar acceso", role: .destructive) { revoking = device }
                        .accessibilityLabel("Quitar acceso a " + device.name)
                }
                Divider()
            }
            if !model.deviceNotice.isEmpty { Text(model.deviceNotice).font(.callout) }
            if adding {
                TextField("Nombre del equipo", text: $name).textFieldStyle(.roundedBorder)
                Text("Dirección del iPhone en el hotspot").font(.caption)
                TextField("Dirección IPv4", text: $gateway).keyboardType(.decimalPad).textFieldStyle(.roundedBorder)
                HStack {
                    Button("Guardar equipo") {
                        if model.addDevice(name: name, gateway: gateway) { name = ""; adding = false }
                    }
                    Button("Cancelar") { adding = false; name = "" }
                }
            } else {
                Button("Añadir equipo") { adding = true }
            }
        }
        .alert("¿Quitar acceso?", isPresented: Binding(get: { revoking != nil },
              set: { if !$0 { revoking = nil } }), presenting: revoking) { device in
            Button("Quitar acceso", role: .destructive) { model.revoke(device) }
            Button("Cancelar", role: .cancel) {}
        } message: { device in
            Text("Se cerrarán las conexiones de " + device.name + " y su archivo de configuración dejará de funcionar.")
        }
    }
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
                        Button("Cerrar emparejamiento") { model.forget() }
                        DeviceList(model: model)
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
