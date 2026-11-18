import Foundation
import Network
import Security

// Wire v1. Every connection represents exactly one destination.
enum Wire {
    static let maxPayload = 65_507
    static let maxHandshake = 4_096
    static let maxSessions = 96
    static let maxUnauthenticatedSessions = 32
    static let handshakeTimeout = 12.0
    static let idleTimeout = 120.0
    static func frame(_ kind: UInt8, _ payload: Data = Data()) -> Data {
        var bytes = Data([kind])
        var length = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
        bytes.append(payload)
        return bytes
    }
    static func json(_ object: [String: Any]) -> Data {
        ((try? JSONSerialization.data(withJSONObject: object)) ?? Data()) + Data([10])
    }
    static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == 64, y.count == 64 else { return false }
        var difference: UInt8 = 0
        for index in x.indices { difference |= x[index] ^ y[index] }
        return difference == 0
    }
    static func validToken(_ token: String) -> Bool {
        token.utf8.count == 64 && token.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    static func validHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 253, !host.contains("%") else { return false }
        // IP literals are accepted without local DNS. Hostnames must be ASCII IDNA A-labels.
        if IPv4Address(host) != nil || IPv6Address(host) != nil { return true }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
            label.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }
}

struct PairingPackage: Decodable {
    let v: Int
    let server_port: UInt16
    let pkcs12_base64: String
    let pkcs12_password: String
    let token: String
    let certificate_sha256: String

    func identity() throws -> SecIdentity {
        guard v == 1, server_port > 0, Wire.validToken(token),
              Wire.validToken(certificate_sha256),
              let bytes = Data(base64Encoded: pkcs12_base64), bytes.count <= 65_536 else {
            throw TunnelError.invalidPairing
        }
        var items: CFArray?
        let options = [kSecImportExportPassphrase as String: pkcs12_password] as CFDictionary
        let status = SecPKCS12Import(bytes as CFData, options, &items)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
        guard let array = items as? [[String: Any]],
              let item = array.first, let raw = item[kSecImportItemIdentity as String] else {
            throw TunnelError.invalidPairing
        }
        // SecPKCS12Import guarantees the returned identity's Core Foundation type.
        guard CFGetTypeID(raw as CFTypeRef) == SecIdentityGetTypeID() else { throw TunnelError.invalidPairing }
        return raw as! SecIdentity
    }
}

enum TunnelError: Error { case invalidPairing, invalidFrame, disconnected }

// One outstanding read at a time, bounded to maxPayload+header. Caller owns sequencing.
final class WireReader {
    private let connection: NWConnection
    private var buffer = Data()
    private var ended = false
    init(_ connection: NWConnection) { self.connection = connection }

    func exact(_ count: Int, completion: @escaping (Result<Data, Error>) -> Void) {
        guard count >= 0, count <= Wire.maxPayload else { completion(.failure(TunnelError.invalidFrame)); return }
        if buffer.count >= count {
            let result = Data(buffer.prefix(count)); buffer.removeFirst(count)
            completion(.success(result)); return
        }
        guard !ended else { completion(.failure(TunnelError.disconnected)); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: max(1, count - buffer.count)) { data, _, complete, error in
            if let data = data { self.buffer.append(data) }
            self.ended = complete
            if let error = error { completion(.failure(error)); return }
            self.exact(count, completion: completion)
        }
    }

    func line(completion: @escaping (Result<Data, Error>) -> Void) {
        if let newline = buffer.firstIndex(of: 10) {
            guard buffer.distance(from: buffer.startIndex, to: newline) <= Wire.maxHandshake else {
                completion(.failure(TunnelError.invalidFrame)); return
            }
            let result = Data(buffer[..<newline]); buffer.removeSubrange(...newline)
            completion(.success(result)); return
        }
        guard !ended, buffer.count <= Wire.maxHandshake else { completion(.failure(TunnelError.invalidFrame)); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1024) { data, _, complete, error in
            if let data = data { self.buffer.append(data) }
            self.ended = complete
            if let error = error { completion(.failure(error)); return }
            self.line(completion: completion)
        }
    }
}
