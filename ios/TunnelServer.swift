import Foundation
import Network
import Security

final class TunnelServer {
    private let queue = DispatchQueue(label: "CellularTunnel.server")
    private var listener: NWListener?
    private var sessions: [UUID: TunnelSession] = [:]
    private var devices: [PairedDevice] = []
    private var identity: SecIdentity?
    var onStatus: ((String, Int) -> Void)?
    var onFailure: (() -> Void)?

    func start(package: PairingPackage, devices: [PairedDevice]) throws {
        let identity = try package.identity()
        guard let wrapped = sec_identity_create(identity) else { throw TunnelError.invalidPairing }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(tls.securityProtocolOptions, wrapped)
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        guard let port = NWEndpoint.Port(rawValue: package.server_port) else { throw TunnelError.invalidPairing }
        let server = try NWListener(using: parameters, on: port)
        queue.async { [self, server] in
            self.stopOnQueue()
            self.devices = devices
            self.identity = identity
            self.listener = server
            server.stateUpdateHandler = { [weak self, weak server] state in
                guard let self = self, let server = server, self.listener === server else { return }
                switch state {
                case .ready: self.publish("Listo. Puerto \(package.server_port). Mantén esta app abierta.")
                case .failed:
                    self.stopOnQueue()
                    DispatchQueue.main.async { [weak self] in self?.onFailure?() }
                default: break
                }
            }
            server.newConnectionHandler = { [weak self] connection in
                guard let self = self, self.listener === server, self.sessions.count < Wire.maxSessions,
                      self.sessions.values.lazy.filter({ $0.deviceID == nil }).count < Wire.maxUnauthenticatedSessions else {
                    connection.cancel(); return
                }
                let id = UUID()
                let session = TunnelSession(connection: connection, queue: self.queue, authenticate: { [weak self] token in
                    guard let self else { return nil }
                    return PairedDevice.identify(token, in: self.devices)
                }) { [weak self] in
                    self?.sessions.removeValue(forKey: id)
                    self?.publish("Servidor activo; salida solo celular.")
                }
                self.sessions[id] = session
                self.publish("Servidor activo; salida solo celular.")
                session.start()
            }
            server.start(queue: self.queue)
        }
    }

    func stop() { queue.async { self.stopOnQueue(); self.publish("Detenido.") } }
    func updateDevices(_ devices: [PairedDevice]) {
        queue.sync {
            self.devices = devices
            let allowed = Set(devices.map(\.id))
            let revoked = sessions.values.filter { session in
                session.deviceID.map { !allowed.contains($0) } ?? false
            }
            revoked.forEach { $0.cancel() }
        }
    }
    private func stopOnQueue() {
        listener?.newConnectionHandler = nil
        listener?.stateUpdateHandler = nil
        listener?.cancel(); listener = nil
        let current = Array(sessions.values)
        sessions.removeAll()
        current.forEach { $0.cancel() }
        devices.removeAll()
        identity = nil
    }
    private func publish(_ text: String) {
        let count = sessions.count
        DispatchQueue.main.async { [weak self] in self?.onStatus?(text, count) }
    }
}

private final class TunnelSession {
    private let client: NWConnection
    private let reader: WireReader
    private let authenticate: (String) -> UUID?
    private let queue: DispatchQueue
    private var remote: NWConnection?
    private var timer: DispatchSourceTimer?
    private var done = false
    private var acknowledged = false
    private(set) var deviceID: UUID?
    private var udp = false
    private var clientFIN = false
    private var remoteFIN = false
    private var clientFINWritten = false
    private var remoteFINWritten = false
    private let onClose: () -> Void

    init(connection: NWConnection, queue: DispatchQueue, authenticate: @escaping (String) -> UUID?,
         onClose: @escaping () -> Void) {
        client = connection; reader = WireReader(connection)
        self.authenticate = authenticate; self.queue = queue; self.onClose = onClose
    }

    func start() {
        armTimer(Wire.handshakeTimeout)
        client.stateUpdateHandler = { [weak self] state in
            guard let self = self, !self.done else { return }
            switch state {
            case .ready: self.handshake()
            case .failed, .cancelled: self.cancel()
            default: break
            }
        }
        client.start(queue: queue)
    }

    func cancel() {
        guard !done else { return }
        done = true
        timer?.cancel(); timer = nil
        client.stateUpdateHandler = nil; client.cancel()
        remote?.stateUpdateHandler = nil; remote?.cancel(); remote = nil
        onClose()
    }

    private func armTimer(_ seconds: Double = Wire.idleTimeout) {
        timer?.cancel()
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + seconds)
        source.setEventHandler { [weak self] in self?.cancel() }
        timer = source; source.resume()
    }

    private func handshake() {
        reader.line { [weak self] result in
            guard let self = self, !self.done else { return }
            guard case .success(let bytes) = result,
                  let object = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                  let version = object["v"] as? Int, version == 1,
                  let supplied = object["token"] as? String, let deviceID = self.authenticate(supplied),
                  let transport = object["transport"] as? String, ["tcp", "udp"].contains(transport),
                  let host = object["host"] as? String, Wire.validHost(host),
                  let port = object["port"] as? Int, (1...65535).contains(port) else {
                self.reject(); return
            }
            self.deviceID = deviceID
            self.udp = transport == "udp"
            let parameters: NWParameters = self.udp ? .udp : .tcp
            parameters.requiredInterfaceType = .cellular
            // The domain is deliberately resolved on the iPhone, not on the Mac.
            let remote = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: UInt16(port))!, using: parameters)
            self.remote = remote
            remote.stateUpdateHandler = { [weak self] state in
                guard let self = self, !self.done else { return }
                switch state {
                case .ready:
                    guard !self.acknowledged else { return }
                    guard remote.currentPath?.usesInterfaceType(.cellular) == true else { self.reject(); return }
                    if let path = remote.currentPath {
                        print("[CellularTunnel] cellular path ipv4=\(path.supportsIPv4) ipv6=\(path.supportsIPv6)")
                        fflush(stdout)
                    }
                    self.acknowledged = true
                    self.client.send(content: Wire.json(["ok": true, "max_sessions": Wire.maxSessions]), completion: .contentProcessed { [weak self] error in
                        guard let self = self, !self.done else { return }
                        if error != nil { self.cancel(); return }
                        self.armTimer()
                        self.readFrame()
                        self.readRemote()
                    })
                case .waiting(let error):
                    print("[CellularTunnel] cellular connection waiting: \(error)")
                    fflush(stdout)
                case .failed(let error):
                    print("[CellularTunnel] cellular connection failed: \(error)")
                    fflush(stdout)
                    if self.acknowledged { self.fail() } else { self.reject() }
                default: break
                }
            }
            remote.start(queue: self.queue)
        }
    }

    private func reject() {
        guard !done else { return }
        client.send(content: Wire.json(["ok": false, "error": "connection_rejected"]), completion: .contentProcessed { [weak self] _ in self?.cancel() })
    }

    private func fail() {
        guard !done else { return }
        // Do not expose endpoints, tokens, raw network errors or payloads in logs.
        client.send(content: Wire.frame(69, Data("remote_connection_failed".utf8)), completion: .contentProcessed { [weak self] _ in self?.cancel() })
    }

    private func readFrame() {
        guard !done else { return }
        reader.exact(5) { [weak self] result in
            guard let self = self, !self.done else { return }
            guard case .success(let header) = result else { self.cancel(); return }
            let bytes = Array(header)
            let kind = bytes[0]
            let length = bytes.dropFirst().reduce(0) { ($0 << 8) | Int($1) }
            guard length <= Wire.maxPayload, [68, 70, 69].contains(kind),
                  kind != 70 || length == 0, kind != 69 || length <= 4096,
                  !self.clientFIN else { self.fail(); return }
            self.reader.exact(length) { [weak self] body in
                guard let self = self, !self.done else { return }
                guard case .success(let payload) = body else { self.cancel(); return }
                self.armTimer()
                if kind == 69 { self.cancel(); return }
                if kind == 70 {
                    self.clientFIN = true
                    if self.udp { self.cancel(); return }
                    self.remote?.send(content: nil, contentContext: .finalMessage, isComplete: true,
                                      completion: .contentProcessed { [weak self] error in
                        guard let self = self, !self.done else { return }
                        if error != nil { self.fail(); return }
                        self.clientFINWritten = true
                        if self.remoteFINWritten { self.cancel() }
                    })
                    return
                }
                self.remote?.send(content: payload, completion: .contentProcessed { [weak self] error in
                    guard let self = self, !self.done else { return }
                    if error != nil { self.fail(); return }
                    // Backpressure: do not read next client frame until this send completes.
                    self.readFrame()
                })
            }
        }
    }

    private func readRemote() {
        guard !done, let remote = remote else { return }
        let receive: (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void = { [weak self] data, _, complete, error in
            guard let self = self, !self.done else { return }
            if error != nil { self.fail(); return }
            if let data = data, !data.isEmpty || self.udp {
                guard data.count <= Wire.maxPayload else { self.fail(); return }
                self.armTimer()
                self.client.send(content: Wire.frame(68, data), completion: .contentProcessed { [weak self] error in
                    guard let self = self, !self.done else { return }
                    if error != nil { self.cancel(); return }
                    if complete && !self.udp { self.sendFIN() } else { self.readRemote() }
                })
            } else if complete && !self.udp { self.sendFIN() }
            else { self.readRemote() }
        }
        if udp { remote.receiveMessage(completion: receive) }
        else { remote.receive(minimumIncompleteLength: 1, maximumLength: Wire.maxPayload, completion: receive) }
    }

    private func sendFIN() {
        guard !done, !remoteFIN else { return }
        remoteFIN = true
        client.send(content: Wire.frame(70), completion: .contentProcessed { [weak self] error in
            guard let self = self, !self.done else { return }
            if error != nil { self.cancel(); return }
            self.remoteFINWritten = true
            if self.clientFINWritten { self.cancel() }
        })
    }
}
