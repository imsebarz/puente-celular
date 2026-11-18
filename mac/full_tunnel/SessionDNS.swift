import Foundation
import SystemConfiguration
import Darwin

func run(_ path: String, _ arguments: [String]) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return process.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : nil
}

let resolver = "172.30.255.2"
func usableResolver() -> Bool {
    guard let route = run("/sbin/route", ["-n", "get", resolver]),
          let interface = route.split(separator: "\n").compactMap({ line -> String? in
              let words = line.split(whereSeparator: { $0.isWhitespace })
              return words.count == 2 && words[0] == "interface:" ? String(words[1]) : nil
          }).first, interface.hasPrefix("utun"),
          let details = run("/sbin/ifconfig", [interface]),
          details.split(separator: "\n").contains(where: { line in
              let fields = line.split(whereSeparator: { $0.isWhitespace })
              return fields.count >= 2 && fields[0] == "inet" && fields[1] == "172.30.255.1"
          }) else { return false }
    for mode in ["+notcp", "+tcp"] {
        guard let result = run("/usr/bin/dig", ["@" + resolver, "example.com.", "A",
                                                 "+short", "+time=3", "+tries=1", mode]),
              result.split(separator: "\n").contains(where: {
                  var addr = in_addr()
                  return inet_pton(AF_INET, String($0), &addr) == 1
              }) else { return false }
    }
    return true
}

// Temporary Dynamic Store entry is removed automatically on process/session exit.
// No persistent network service, Wi-Fi setting or configuration profile is edited.
guard CommandLine.arguments.count == 2, let pid = Int32(CommandLine.arguments[1]), pid > 1,
      (kill(pid, 0) == 0 || errno == EPERM) else {
    fputs("Se requiere el PID activo del motor. DNS del Mac intacto.\n", stderr)
    exit(1)
}
guard usableResolver() else {
    fputs("El DNS del TUN no respondió por la interfaz esperada en UDP y TCP. DNS del Mac intacto.\n", stderr)
    exit(1)
}
guard let store = SCDynamicStoreCreate(nil, "PuenteCelularSessionDNS" as CFString, nil, nil) else {
    fatalError("Could not open SystemConfiguration")
}
let key = "State:/Network/Service/PuenteCelular-\(UUID().uuidString)/DNS" as CFString
let dns: [String: Any] = [
    "ServerAddresses": [resolver],
    "SupplementalMatchDomains": [""],
    "SupplementalMatchOrders": [1],
    "SearchOrder": 1
]
guard SCDynamicStoreAddTemporaryValue(store, key, dns as CFDictionary) else {
    fputs("Could not add temporary DNS: \(String(cString: SCErrorString(SCError()))). Run with administrator permission.\n", stderr)
    exit(1)
}
print("DNS temporal hacia el iPhone activo. Ctrl+C elimina este DNS; termina también al detener sing-box.")
fflush(stdout)
let timer = DispatchSource.makeTimerSource(queue: .main)
timer.schedule(deadline: .now() + 5, repeating: 5)
timer.setEventHandler {
    if (kill(pid, 0) != 0 && errno == ESRCH) || !usableResolver() {
        SCDynamicStoreRemoveValue(store, key)
        exit(1)
    }
}
timer.resume()
withExtendedLifetime(store) { dispatchMain() }
