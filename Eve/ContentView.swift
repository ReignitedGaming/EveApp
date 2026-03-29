import SwiftUI
import WebKit
import Darwin

// AMFI Launch Constraint test — CVE-2025-43253 applicability check
// Tests whether constraint category 127 is enforced on iOS 26
func testAMFIConstraints() -> String {
    var results = "[AMFI Constraint Test]\n"

    // Test 1: Check if posix_spawnattr_setmacpolicyinfo_np exists
    let handle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW)
    if handle != nil {
        results += "libSystem loaded OK\n"

        // Look for the spawn attribute function
        let sym = dlsym(handle, "posix_spawnattr_setmacpolicyinfo_np")
        if sym != nil {
            results += "posix_spawnattr_setmacpolicyinfo_np: FOUND\n"
        } else {
            results += "posix_spawnattr_setmacpolicyinfo_np: NOT FOUND\n"
        }

        let sym2 = dlsym(handle, "posix_spawnattr_set_launch_type_np")
        if sym2 != nil {
            results += "posix_spawnattr_set_launch_type_np: FOUND\n"
        } else {
            results += "posix_spawnattr_set_launch_type_np: NOT FOUND\n"
        }

        dlclose(handle)
    } else {
        results += "libSystem load FAILED\n"
    }

    // Test 2: Try to create spawn attributes
    var attr: posix_spawnattr_t? = nil
    let initResult = posix_spawnattr_init(&attr)
    results += "posix_spawnattr_init: \(initResult == 0 ? "OK" : "FAILED (\(initResult))")\n"

    // Test 3: Check sysctl values
    var enforced: Int32 = -1
    var size = MemoryLayout<Int32>.size
    let r1 = sysctlbyname("security.mac.amfi.launch_constraints_enforced", &enforced, &size, nil, 0)
    results += "launch_constraints_enforced: \(r1 == 0 ? "\(enforced)" : "DENIED (\(errno))")\n"

    var thirdParty: Int32 = -1
    size = MemoryLayout<Int32>.size
    let r2 = sysctlbyname("security.mac.amfi.launch_constraints_3rd_party_allowed", &thirdParty, &size, nil, 0)
    results += "3rd_party_allowed: \(r2 == 0 ? "\(thirdParty)" : "DENIED (\(errno))")\n"

    var ccTypes: Int32 = -1
    size = MemoryLayout<Int32>.size
    let r3 = sysctlbyname("security.mac.amfi.launch_constraints_cc_types_enforced", &ccTypes, &size, nil, 0)
    results += "cc_types_enforced: \(r3 == 0 ? "\(ccTypes)" : "DENIED (\(errno))")\n"

    var devMode: Int32 = -1
    size = MemoryLayout<Int32>.size
    let r4 = sysctlbyname("security.mac.amfi.developer_mode_status", &devMode, &size, nil, 0)
    results += "developer_mode: \(r4 == 0 ? "\(devMode)" : "DENIED (\(errno))")\n"

    // Test 4: Try posix_spawn with category 127 via dlsym
    if attr != nil {
        // Get posix_spawnattr_setmacpolicyinfo_np via dlsym
        let libHandle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOW)

        if let macPolicySym = dlsym(libHandle, "posix_spawnattr_setmacpolicyinfo_np") {
            // Function signature: int posix_spawnattr_setmacpolicyinfo_np(posix_spawnattr_t*, const char*, void*, size_t)
            typealias SetMacPolicyFn = @convention(c) (UnsafeMutablePointer<posix_spawnattr_t?>, UnsafePointer<CChar>, UnsafeRawPointer, Int) -> Int32
            let setMacPolicy = unsafeBitCast(macPolicySym, to: SetMacPolicyFn.self)

            // Build minimal LWCR (Lightweight Constraint) with category 127
            // LWCR format: magic(4) + length(4) + version(4) + constraintCategory(4)
            var lwcr: [UInt8] = []
            // LWCR magic: 0xfade7171
            lwcr += [0xfa, 0xde, 0x71, 0x71]
            // Length: 16 bytes total
            lwcr += [0x00, 0x00, 0x00, 0x10]
            // Version: 1
            lwcr += [0x00, 0x00, 0x00, 0x01]
            // Constraint category: 127
            lwcr += [0x00, 0x00, 0x00, 0x7f]

            let policyResult = lwcr.withUnsafeBufferPointer { buf in
                "AMFI".withCString { name in
                    setMacPolicy(&attr, name, buf.baseAddress!, buf.count)
                }
            }
            results += "setmacpolicyinfo(AMFI, cat127): \(policyResult) (\(policyResult == 0 ? "OK" : String(cString: strerror(policyResult))))\n"
        } else {
            results += "setmacpolicyinfo: symbol not found\n"
        }

        // Now try posix_spawn with the category 127 constraints set
        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, "/usr/bin/true", nil, &attr, nil, nil)
        results += "posix_spawn /usr/bin/true (cat127): \(spawnResult) (\(String(cString: strerror(spawnResult))))\n"
        if spawnResult == 0 {
            results += ">>> PROCESS SPAWNED WITH CAT 127! PID: \(pid)\n"
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            results += "Exit status: \((status >> 8) & 0xff)\n"
        }

        if libHandle != nil { dlclose(libHandle) }
        posix_spawnattr_destroy(&attr)
    }

    // Test 5: Check if process-related functions exist via dlsym
    let sysHandle = dlopen(nil, RTLD_NOW)
    if sysHandle != nil {
        let hasFork = dlsym(sysHandle, "fork") != nil
        let hasExecve = dlsym(sysHandle, "execve") != nil
        let hasPosixSpawn = dlsym(sysHandle, "posix_spawn") != nil
        let hasSystem = dlsym(sysHandle, "system") != nil
        let hasPopen = dlsym(sysHandle, "popen") != nil
        results += "dlsym fork: \(hasFork)\n"
        results += "dlsym execve: \(hasExecve)\n"
        results += "dlsym posix_spawn: \(hasPosixSpawn)\n"
        results += "dlsym system: \(hasSystem)\n"
        results += "dlsym popen: \(hasPopen)\n"
        dlclose(sysHandle)
    }

    // Test 6: Check sandbox profile
    results += "getpid: \(getpid())\n"
    results += "getuid: \(getuid())\n"
    results += "geteuid: \(geteuid())\n"

    // Test 7: Check Mach service reachability via NSConnection
    results += "\n[Services]\n"
    let services = ["com.apple.springboard.services", "com.apple.installd",
                    "com.apple.trustd", "com.apple.amfid",
                    "com.apple.containermanagerd", "com.apple.runningboardd"]
    for svc in services {
        let exists = dlsym(dlopen(nil, RTLD_NOW), svc) != nil
        results += "  \(svc): \(exists ? "sym" : "no")\n"
    }

    // Test 8: Can we write outside our container?
    let testPaths = ["/tmp/eve_test", "/var/mobile/eve_test", "/var/tmp/eve_test"]
    for path in testPaths {
        do {
            try "test".write(toFile: path, atomically: true, encoding: .utf8)
            results += "write \(path): YES\n"
            try? FileManager.default.removeItem(atPath: path)
        } catch {
            results += "write \(path): NO\n"
        }
    }

    return results
}

struct ContentView: View {
    @State private var serverIP = "192.168.0.222"
    @State private var connected = false
    @State private var testResults = ""
    @State private var showingTest = false

    var body: some View {
        VStack {
            if showingTest {
                ScrollView {
                    Text(testResults)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(.green)
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .background(Color.black)
                Button("Back") { showingTest = false }
                    .padding()
            } else if connected {
                WebView(url: URL(string: "http://\(serverIP):9192/chat")!)
                    .edgesIgnoringSafeArea(.all)
            } else {
                VStack(spacing: 20) {
                    Image(systemName: "shield.checkered")
                        .font(.system(size: 80))
                        .foregroundColor(.green)
                    Text("EVE")
                        .font(.largeTitle)
                        .bold()
                    Text("Living AI Companion")
                        .foregroundColor(.gray)
                    TextField("Desktop IP", text: $serverIP)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                    Button("Connect") {
                        connected = true
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.green)

                    Button("AMFI Test") {
                        testResults = testAMFIConstraints()
                        showingTest = true
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.red)
                }
                .padding()
            }
        }
    }
}

struct WebView: UIViewRepresentable {
    let url: URL
    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.load(URLRequest(url: url))
        return webView
    }
    func updateUIView(_ uiView: WKWebView, context: Context) {}
}
