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
            results += "Exit status: \((status >> 8) & 0xff)\n"
        }
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

    // Test 7: Enumerate reachable Mach services via dlsym
    results += "\n[Mach Services]\n"

    typealias BootstrapLookUpFn = @convention(c) (mach_port_t, UnsafePointer<CChar>, UnsafeMutablePointer<mach_port_t>) -> kern_return_t

    let bsHandle = dlopen("/usr/lib/system/libxpc.dylib", RTLD_NOW)
    let bsLookupSym = bsHandle != nil ? dlsym(bsHandle, "bootstrap_look_up") : nil

    if let sym = bsLookupSym {
        let bsLookup = unsafeBitCast(sym, to: BootstrapLookUpFn.self)

        let servicesToTest = [
            "com.apple.springboard.services",
            "com.apple.backboardd",
            "com.apple.lsd.mapdb",
            "com.apple.installd",
            "com.apple.mobile.installd",
            "com.apple.runningboardd",
            "com.apple.frontboard.systemappservices",
            "com.apple.mediaserverd",
            "com.apple.photoanalysisd",
            "com.apple.bookassetd",
            "com.apple.itunesstored",
            "com.apple.cfprefsd.daemon",
            "com.apple.containermanagerd",
            "com.apple.mobileassetd",
            "com.apple.trustd",
            "com.apple.debugserver",
            "com.apple.amfid",
        ]
        for svc in servicesToTest {
            var port: mach_port_t = 0
            let kr = svc.withCString { name in
                bsLookup(bootstrap_port, name, &port)
            }
            if kr == KERN_SUCCESS && port != 0 {
                results += "  \(svc): PORT \(port)\n"
            }
        }
    } else {
        results += "  bootstrap_look_up not found\n"
    }
    if bsHandle != nil { dlclose(bsHandle) }

    // Test 8: Try to get our own task port (get-task-allow test)
    let selfTask = mach_task_self_
    results += "mach_task_self: \(selfTask)\n"
    var taskInfo = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
    let kr = withUnsafeMutablePointer(to: &taskInfo) { ptr in
        ptr.withMemoryRebound(to: Int32.self, capacity: Int(count)) { intPtr in
            task_info(selfTask, task_flavor_t(MACH_TASK_BASIC_INFO), intPtr, &count)
        }
    }
    results += "task_info: \(kr == KERN_SUCCESS ? "OK" : "FAILED (\(kr))")\n"
    if kr == KERN_SUCCESS {
        results += "  resident_size: \(taskInfo.resident_size)\n"
        results += "  virtual_size: \(taskInfo.virtual_size)\n"
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
