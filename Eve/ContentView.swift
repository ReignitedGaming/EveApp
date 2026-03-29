import SwiftUI
import WebKit

struct ContentView: View {
    @State private var serverIP = "192.168.0.222"
    @State private var connected = false
    
    var body: some View {
        VStack {
            if connected {
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
