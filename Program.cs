using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

class ProxyServer {
    private static List<string> blacklist = new List<string>();
    private const int proxyPort = 8080;
    private const string blacklistFile = "blacklist.txt";
    private static Dictionary<string, DateTime> lastLoggedTimes = new Dictionary<string, DateTime>();
    private const double logIntervalSeconds = 0.3;
    private static readonly List<string> ignoredDomains = new List<string> { "gvt1.com", "digicert.com", "ocsp.", "crl.", "msftconnecttest.com" };

    static void Main(string[] args) {
        LoadBlacklist();

        Socket proxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        proxySocket.Bind(new IPEndPoint(IPAddress.Any, proxyPort));
        proxySocket.Listen(10);

        Console.WriteLine($"Proxy server started on port {proxyPort}...");

        while (true) {
            Socket clientSocket = proxySocket.Accept();
            Thread clientThread = new Thread(() => HandleClient(clientSocket));
            clientThread.Start();
        }
    }

    static void LoadBlacklist() {
        try {
            if (File.Exists(blacklistFile)) {
                blacklist.AddRange(File.ReadAllLines(blacklistFile));
                Console.WriteLine("Blacklist loaded:");
                foreach (var item in blacklist) {
                    if (!string.IsNullOrWhiteSpace(item))
                        Console.WriteLine($"- {item}");
                }
            }
            else {
                Console.WriteLine("Blacklist file not found. Creating an empty one.");
                File.Create(blacklistFile).Close();
            }
        }
        catch (Exception ex) {
            Console.WriteLine($"Error loading blacklist: {ex.Message}");
        }
    }

    static void HandleClient(Socket clientSocket) {
        try {
            NetworkStream clientStream = new NetworkStream(clientSocket);
            string request = ReadRequest(clientStream);

            if (string.IsNullOrEmpty(request)) {
                clientSocket.Close();
                return;
            }

            if (request.StartsWith("CONNECT")) {
                HandleConnectRequest(clientStream, request);
                clientSocket.Close();
                return;
            }

            (string method, string url, string host, int port, string path) = ParseRequest(request);

            if (string.IsNullOrEmpty(method) || string.IsNullOrEmpty(url) || string.IsNullOrEmpty(host)) {
                clientSocket.Close();
                return;
            }

            if (IsIgnoredDomain(host)) {
                clientSocket.Close();
                return;
            }

            if (url.EndsWith("/favicon.ico")) {
                clientSocket.Close();
                return;
            }

            if (IsBlacklisted(host)) {
                SendBlockedResponse(clientStream, url);
                if (ShouldLogRequest(url))
                    Console.WriteLine($"{url} - 403 Forbidden");
                clientSocket.Close();
                return;
            }

            Socket serverSocket = ConnectToServer(host, port);
            if (serverSocket == null) {
                clientSocket.Close();
                return;
            }

            string modifiedRequest = ModifyRequest(request, method, path);
            SendRequestToServer(serverSocket, modifiedRequest);

            RelayResponse(serverSocket, clientStream, url);

            serverSocket.Close();
            clientSocket.Close();
        }
        catch (Exception ex) {
            if (!ex.Message.Contains("Попытка установить соединение была безуспешной"))
                Console.WriteLine($"Error handling client: {ex.Message}");
            clientSocket.Close();
        }
    }

    static void HandleConnectRequest(NetworkStream clientStream, string request) {
        string host = null;
        int port = 0;

        string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0) return;

        string[] connectLine = lines[0].Split(' ');
        if (connectLine.Length < 2) return;

        string hostPort = connectLine[1];
        string[] hostPortParts = hostPort.Split(':');
        if (hostPortParts.Length != 2) return;

        host = hostPortParts[0];
        if (!int.TryParse(hostPortParts[1], out port)) return;

        if (string.IsNullOrEmpty(host)) return;

        if (IsIgnoredDomain(host))
            return;

        if (IsBlacklisted(host)) {
            SendBlockedResponse(clientStream, host);
            if (ShouldLogRequest(host))
                Console.WriteLine($"{host} - 403 Forbidden");
            return;
        }

        try {
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Connect(host, port);
            NetworkStream serverStream = new NetworkStream(serverSocket);

            string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
            byte[] responseBytes = Encoding.ASCII.GetBytes(response);
            clientStream.Write(responseBytes, 0, responseBytes.Length);

            RelayStreams(clientStream, serverStream, host);
            serverSocket.Close();
        }
        catch (Exception ex) {
            if (!ex.Message.Contains("Попытка установить соединение была безуспешной"))
                Console.WriteLine($"Error handling CONNECT: {ex.Message}");
        }
    }

    static void RelayStreams(NetworkStream clientStream, NetworkStream serverStream, string host) {
        Thread clientToServer = new Thread(() => {
            try {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = clientStream.Read(buffer, 0, buffer.Length)) > 0) {
                    serverStream.Write(buffer, 0, bytesRead);
                }
            }
            catch { }
        });

        Thread serverToClient = new Thread(() => {
            try {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = serverStream.Read(buffer, 0, buffer.Length)) > 0) {
                    clientStream.Write(buffer, 0, bytesRead);
                }
            }
            catch { }
        });

        clientToServer.Start();
        serverToClient.Start();
        clientToServer.Join();
        serverToClient.Join();
    }

    static string ReadRequest(NetworkStream clientStream) {
        byte[] buffer = new byte[1024];
        StringBuilder requestBuilder = new StringBuilder();
        int bytesRead;

        try {
            clientStream.ReadTimeout = 2000;
            do {
                bytesRead = clientStream.Read(buffer, 0, buffer.Length);
                requestBuilder.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
            } while (clientStream.DataAvailable);
        }
        catch (IOException) {
           
        }

        return requestBuilder.ToString();
    }

    static (string method, string url, string host, int port, string path) ParseRequest(string request) {
        string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0) return (null, null, null, 0, null);

        string[] firstLine = lines[0].Split(' ');
        if (firstLine.Length < 3) return (null, null, null, 0, null);

        string method = firstLine[0];
        string url = firstLine[1];

        string host = null;
        int port = 80;
        string path = "/";

        if (url.StartsWith("http://")) {
            string uriPart = url.Substring(7);
            int pathIndex = uriPart.IndexOf('/');
            if (pathIndex == -1) {
                host = uriPart;
            }
            else {
                host = uriPart.Substring(0, pathIndex);
                path = uriPart.Substring(pathIndex);
            }

            int portIndex = host.IndexOf(':');
            if (portIndex != -1) {
                if (int.TryParse(host.Substring(portIndex + 1), out port)) {
                    host = host.Substring(0, portIndex);
                }
                else {
                    port = 80;
                }
            }
        }
        else {
            foreach (var line in lines) {
                if (line.StartsWith("Host:")) {
                    host = line.Substring(5).Trim();
                    int portIndex = host.IndexOf(':');
                    if (portIndex != -1) {
                        if (int.TryParse(host.Substring(portIndex + 1), out port)) {
                            host = host.Substring(0, portIndex);
                        }
                        else {
                            port = 80;
                        }
                    }
                    break;
                }
            }
            path = url;
        }

        return (method, url, host, port, path);
    }

    static bool IsBlacklisted(string host) {
        if (string.IsNullOrEmpty(host))
            return false;

        string hostLower = host.ToLower();
        foreach (var item in blacklist) {
            if (string.IsNullOrEmpty(item)) continue;
            string blacklistedDomain = item.ToLower().Trim();

            // Проверяем, совпадает ли домен полностью или является поддоменом
            if (hostLower == blacklistedDomain || hostLower.EndsWith("." + blacklistedDomain)) {
                return true;
            }
            // Проверяем, является ли blacklistedDomain поддоменом host
            if (blacklistedDomain.EndsWith("." + hostLower) || blacklistedDomain == hostLower) {
                return true;
            }
        }
        return false;
    }

    static bool IsIgnoredDomain(string host) {
        if (string.IsNullOrEmpty(host))
            return true;

        foreach (var ignored in ignoredDomains) {
            if (host.ToLower().Contains(ignored.ToLower()))
                return true;
        }
        return false;
    }

    static void SendBlockedResponse(NetworkStream clientStream, string url) {
        string response = "HTTP/1.1 403 Forbidden\r\n" +
                         "Content-Type: text/html\r\n" +
                         "\r\n" +
                         $"<html><body><h1>Access Denied</h1><p>This site is blocked: {url}</p></body></html>";
        byte[] responseBytes = Encoding.ASCII.GetBytes(response);
        clientStream.Write(responseBytes, 0, responseBytes.Length);
    }

    static Socket ConnectToServer(string host, int port) {
        if (string.IsNullOrEmpty(host)) {
            Console.WriteLine($"Error connecting to :{port}: Host is null or empty.");
            return null;
        }

        try {
            Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.ReceiveTimeout = 10000;
            IPAddress[] addresses = Dns.GetHostAddresses(host);
            if (addresses.Length == 0) return null;

            serverSocket.Connect(new IPEndPoint(addresses[0], port));
            return serverSocket;
        }
        catch (Exception ex) {
            if (!ex.Message.Contains("Попытка установить соединение была безуспешной"))
                Console.WriteLine($"Error connecting to {host}:{port}: {ex.Message}");
            return null;
        }
    }

    static string ModifyRequest(string request, string method, string path) {
        string[] lines = request.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length == 0) return request;

        lines[0] = $"{method} {path} HTTP/1.1";
        return string.Join("\r\n", lines);
    }

    static void SendRequestToServer(Socket serverSocket, string request) {
        byte[] requestBytes = Encoding.ASCII.GetBytes(request);
        serverSocket.Send(requestBytes);
    }

    static void RelayResponse(Socket serverSocket, NetworkStream clientStream, string url) {
        byte[] buffer = new byte[1024];
        int bytesRead;
        bool firstChunk = true;
        StringBuilder responseBuilder = new StringBuilder();

        try {
            serverSocket.ReceiveTimeout = 10000;
            while ((bytesRead = serverSocket.Receive(buffer)) > 0) {
                if (firstChunk) {
                    responseBuilder.Append(Encoding.ASCII.GetString(buffer, 0, bytesRead));
                    string response = responseBuilder.ToString();
                    string[] lines = response.Split(new[] { "\r\n" }, StringSplitOptions.None);
                    if (lines.Length > 0) {
                        string[] statusLine = lines[0].Split(' ');
                        if (statusLine.Length >= 3 && ShouldLogRequest(url)) {
                            Console.WriteLine($"{url} - {statusLine[1]} {statusLine[2]}");
                        }
                    }
                    firstChunk = false;
                }
                clientStream.Write(buffer, 0, bytesRead);
            }
        }
        catch (IOException) {
           
        }
    }

    static bool ShouldLogRequest(string url) {
        if (string.IsNullOrEmpty(url)) return false;
        if (url.EndsWith("/favicon.ico")) return false;

        DateTime now = DateTime.Now;
        if (lastLoggedTimes.TryGetValue(url, out DateTime lastLogged)) {
            if ((now - lastLogged).TotalSeconds < logIntervalSeconds) {
                return false;
            }
        }
        lastLoggedTimes[url] = now;
        return true;
    }
}