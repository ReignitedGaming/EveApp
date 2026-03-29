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

    // Test 4: Try posix_spawn (will likely fail but the ERROR tells us what's checked)
    if attr != nil {
        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, "/usr/bin/true", nil, &attr, nil, nil)
        results += "posix_spawn /usr/bin/true: \(spawnResult) (\(String(cString: strerror(spawnResult))))\n"
        if spawnResult == 0 {
            results += "PID: \(pid) — PROCESS SPAWNED!\n"
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            results += "Exit status: \(WEXITSTATUS(status))\n"
        }
        posix_spawnattr_destroy(&attr)
    }

    // Test 5: Try fork (likely blocked)
    results += "fork test: "
    let forkPid = fork()
    if forkPid == 0 {
        // Child — exit immediately
        _exit(0)
    } else if forkPid > 0 {
        results += "SUCCEEDED (child pid \(forkPid))\n"
        var status: Int32 = 0
        waitpid(forkPid, &status, 0)
    } else {
        results += "FAILED (errno \(errno))\n"
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
