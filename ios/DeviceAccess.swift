import CryptoKit
import Foundation
import Network
import Security

enum DeviceAccessError: LocalizedError {
    case invalidName, duplicateName, invalidGateway, full, missing, storage(OSStatus)

    var errorDescription: String? {
        switch self {
        case .invalidName: return "Escribe un nombre de entre 1 y 64 caracteres."
        case .duplicateName: return "Ya hay un equipo con ese nombre."
        case .invalidGateway: return "Escribe la dirección IPv4 privada del iPhone en el hotspot."
        case .full: return "Se alcanzó el límite de 64 equipos."
        case .missing: return "Este equipo ya no tiene acceso."
        case .storage: return "No se pudo acceder al llavero. Desbloquea el iPhone y vuelve a intentar."
        }
    }
}

struct PairedDevice: Codable, Identifiable {
    let id: UUID
    let name: String
    let token: String
    let socksPassword: String?
    let gateway: String?

    static func identify(_ token: String, in devices: [Self]) -> UUID? {
        guard Wire.validToken(token) else { return nil }
        return devices.first { Wire.constantTimeEqual(token, $0.token) }?.id
    }

    static func initial(token: String) -> Self {
        Self(id: UUID(), name: "Emparejamiento inicial", token: token, socksPassword: nil, gateway: nil)
    }

    static func issue(name rawName: String, gateway rawGateway: String, among devices: [Self]) throws -> Self {
        let name = rawName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...64).contains(name.count), !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else {
            throw DeviceAccessError.invalidName
        }
        guard !devices.contains(where: { $0.name.localizedCaseInsensitiveCompare(name) == .orderedSame }) else {
            throw DeviceAccessError.duplicateName
        }
        guard devices.count < 64 else { throw DeviceAccessError.full }
        let gateway = rawGateway.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let address = IPv4Address(gateway) else { throw DeviceAccessError.invalidGateway }
        let octets = Array(address.rawValue)
        guard octets[0] == 10 || (octets[0] == 172 && (16...31).contains(octets[1]))
                || (octets[0] == 192 && octets[1] == 168) else { throw DeviceAccessError.invalidGateway }
        func secret() -> String {
            SymmetricKey(size: .bits256).withUnsafeBytes { $0.map { String(format: "%02x", $0) }.joined() }
        }
        return Self(id: UUID(), name: name, token: secret(), socksPassword: secret(), gateway: gateway)
    }

    func profile(for package: PairingPackage) throws -> Data {
        guard let gateway, let socksPassword else { throw DeviceAccessError.missing }
        return try JSONSerialization.data(withJSONObject: [
            "server_host": gateway, "server_port": package.server_port,
            "certificate_sha256": package.certificate_sha256, "token": token,
            "socks_username": "local", "socks_password": socksPassword
        ], options: [.prettyPrinted, .sortedKeys])
    }
}

struct DeviceStore {
    let fingerprint: String

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "PuenteCelular.devices.v1",
         kSecAttrAccount as String: fingerprint]
    }

    func load(initialToken: String) throws -> [PairedDevice] {
        var request = query
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound {
            let devices = [PairedDevice.initial(token: initialToken)]
            var item = query
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            item[kSecValueData as String] = try JSONEncoder().encode(devices)
            let added = SecItemAdd(item as CFDictionary, nil)
            guard added == errSecSuccess else { throw DeviceAccessError.storage(added) }
            return devices
        }
        guard status == errSecSuccess, let data = result as? Data else { throw DeviceAccessError.storage(status) }
        return try JSONDecoder().decode([PairedDevice].self, from: data)
    }

    func save(_ devices: [PairedDevice]) throws {
        let change = [kSecValueData as String: try JSONEncoder().encode(devices)]
        let status = SecItemUpdate(query as CFDictionary, change as CFDictionary)
        guard status == errSecSuccess else { throw DeviceAccessError.storage(status) }
    }
}
