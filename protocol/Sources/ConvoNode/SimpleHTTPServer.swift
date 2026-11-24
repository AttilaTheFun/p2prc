import Foundation
import ConvoNet
#if canImport(Network)
import Network
#endif

#if canImport(Network)
/// A minimal HTTP/1.1 server good enough for demos: parses the request line,
/// headers, and (Content-Length-delimited) body, hands the request to a
/// handler, sends the response, closes.
public final class SimpleHTTPServer: @unchecked Sendable {
    public typealias RequestHandler = @Sendable (HTTPRequest) -> HTTPResponse

    private let listener: NWListener
    private let queue = DispatchQueue(label: "p2prc.simplehttp")
    private let handler: RequestHandler
    public let port: UInt16

    public init(port: UInt16, requestHandler: @escaping RequestHandler) throws {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw NSError(domain: "SimpleHTTPServer", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid port"])
        }
        self.port = port
        self.handler = requestHandler
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        self.listener = try NWListener(using: parameters, on: nwPort)
    }

    /// Path-only convenience for GET-style servers.
    public convenience init(
        port: UInt16,
        handler: @escaping @Sendable (_ path: String) -> (status: Int, contentType: String, body: Data)
    ) throws {
        try self.init(port: port) { request in
            let (status, contentType, body) = handler(request.path)
            return HTTPResponse(status: status, contentType: contentType, body: body)
        }
    }

    public func start() {
        listener.stateUpdateHandler = { [port = port] state in
            if case .failed(let error) = state {
                FileHandle.standardError.write(Data("SimpleHTTPServer: listener on port \(port) failed: \(error)\n".utf8))
            }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            connection.start(queue: self.queue)
            self.receiveRequest(on: connection, buffered: Data(), peer: Self.describe(connection.endpoint))
        }
        listener.start(queue: queue)
    }

    public func stop() {
        listener.cancel()
    }

    /// "host:port" for the endpoint types a listener actually produces.
    static func describe(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case .hostPort(let host, let port):
            var text = "\(host)"
            // NWEndpoint.Host renders IPv6 with a scope suffix ("fe80::1%en0")
            // and IPv4 plainly; strip the scope so the result is dialable.
            if let percent = text.firstIndex(of: "%") { text = String(text[..<percent]) }
            return "\(text):\(port.rawValue)"
        default:
            return ""
        }
    }

    private func receiveRequest(on connection: NWConnection, buffered: Data, peer: String) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if error != nil {
                connection.cancel()
                return
            }
            var buffer = buffered
            if let data { buffer.append(data) }

            if let headerEnd = buffer.range(of: Data("\r\n\r\n".utf8)) {
                let head = String(data: buffer[..<headerEnd.lowerBound], encoding: .utf8) ?? ""
                let lines = head.components(separatedBy: "\r\n")
                let requestLine = lines.first ?? ""
                let parts = requestLine.split(separator: " ")
                let method = parts.count > 0 ? String(parts[0]) : "GET"
                let path = parts.count > 1 ? String(parts[1]) : "/"

                var contentLength = 0
                var headers: [String: String] = [:]
                for line in lines.dropFirst() {
                    guard let colon = line.firstIndex(of: ":") else { continue }
                    let name = line[line.startIndex..<colon].lowercased()
                    let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                    headers[name] = value
                    if name == "content-length" {
                        contentLength = Int(value) ?? 0
                    }
                }

                let bodyStart = headerEnd.upperBound
                let bodyAvailable = buffer.count - buffer.distance(from: buffer.startIndex, to: bodyStart)
                if bodyAvailable >= contentLength {
                    let body = buffer[bodyStart...].prefix(contentLength)
                    let request = HTTPRequest(
                        method: method, path: path, body: Data(body), headers: headers, peer: peer
                    )
                    self.respond(on: connection, request: request)
                } else if isComplete {
                    connection.cancel()
                } else {
                    self.receiveRequest(on: connection, buffered: buffer, peer: peer)
                }
            } else if isComplete {
                connection.cancel()
            } else {
                self.receiveRequest(on: connection, buffered: buffer, peer: peer)
            }
        }
    }

    private func respond(on connection: NWConnection, request: HTTPRequest) {
        let response = handler(request)
        let statusText: String
        switch response.status {
        case 200: statusText = "OK"
        case 204: statusText = "No Content"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        default: statusText = "Error"
        }
        var head = "HTTP/1.1 \(response.status) \(statusText)\r\n"
        head += "Content-Type: \(response.contentType)\r\n"
        head += "Content-Length: \(response.body.count)\r\n"
        head += "Cache-Control: no-store\r\n"
        // A signaling server is reached cross-origin by every browser client
        // it helps, and those clients read the body — so the responses have
        // to be CORS-permissive. There is nothing to protect here: the server
        // holds only sealed blobs and public advertisements, and it already
        // answers anyone who can open a socket to it.
        head += "Access-Control-Allow-Origin: *\r\n"
        head += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        head += "Access-Control-Allow-Headers: Content-Type, \(NodeAPI.authHeader)\r\n"
        head += "Access-Control-Max-Age: 86400\r\n"
        head += "Connection: close\r\n\r\n"
        var data = Data(head.utf8)
        data.append(response.body)
        connection.send(content: data, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}
#endif
