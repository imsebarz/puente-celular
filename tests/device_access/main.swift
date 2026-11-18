import Foundation
import Security

// Use a new account per run. Delete only the test item from the current keychain.
let fingerprint = UUID().uuidString
let store = DeviceStore(fingerprint: fingerprint)
defer {
    let query = [kSecClass as String: kSecClassGenericPassword,
                 kSecAttrAccount as String: fingerprint,
                 kSecAttrService as String: "PuenteCelular.devices.v1"] as [String: Any]
    SecItemDelete(query as CFDictionary)
}
let initialToken = String(repeating: "a", count: 64)
let initial = try store.load(initialToken: initialToken)
precondition(initial.count == 1 && initial[0].token == initialToken)
let alice = try PairedDevice.issue(name: "Portátil", gateway: "172.20.10.1", among: initial)
let bob = try PairedDevice.issue(name: "Escritorio", gateway: "172.20.10.1", among: initial + [alice])
precondition(alice.id != bob.id && alice.token != bob.token && alice.socksPassword != bob.socksPassword)
precondition(Wire.validToken(alice.token) && Wire.validToken(bob.token))
let invalidName = try? PairedDevice.issue(name: "  PORTÁTIL  ", gateway: "172.20.10.1", among: [alice])
let publicGateway = try? PairedDevice.issue(name: "Otro", gateway: "8.8.8.8", among: [alice])
precondition(invalidName == nil && publicGateway == nil)
let package = PairingPackage(v: 1, server_port: 49443, pkcs12_base64: "", pkcs12_password: "",
                             token: initialToken, certificate_sha256: String(repeating: "b", count: 64))
let exported = try JSONSerialization.jsonObject(with: alice.profile(for: package)) as! [String: Any]
precondition(Set(exported.keys) == ["server_host", "server_port", "certificate_sha256", "token", "socks_username", "socks_password"])
precondition(exported["token"] as? String == alice.token && exported["certificate_sha256"] as? String == package.certificate_sha256)
try store.save(initial + [alice, bob])
let loaded = try store.load(initialToken: initialToken)
precondition(PairedDevice.identify(alice.token, in: loaded) == alice.id)
try store.save([bob])
let surviving = try store.load(initialToken: initialToken)
precondition(PairedDevice.identify(alice.token, in: surviving) == nil)
precondition(PairedDevice.identify(initialToken, in: surviving) == nil)
precondition(PairedDevice.identify(bob.token, in: surviving) == bob.id)
try store.save([])
let empty = try store.load(initialToken: initialToken)
precondition(empty.isEmpty)
print("PASS: independent profiles, export, persistence, selective and final revocation")
