import ConvoFoundation

/// A request and a response as the node handles them, whatever carries them:
/// the socket servers in ConvoNode, a Worker's fetch handler, a test.
public struct HTTPRequest: Sendable {
    public let method: String
    public let path: String
    public let body: Data
    /// Header names are lowercased for case-insensitive lookup.
    public let headers: [String: String]
    /// The caller's address as this process sees it, "host:port".
    ///
    /// This is what lets a bootstrapper answer "what does my address look
    /// like from outside?" for someone else — the job a STUN server does,
    /// done by a peer instead.
    public let peer: String

    public init(
        method: String,
        path: String,
        body: Data,
        headers: [String: String] = [:],
        peer: String = ""
    ) {
        self.method = method
        self.path = path
        self.body = body
        self.headers = headers
        self.peer = peer
    }
}

public struct HTTPResponse: Sendable {
    public var status: Int
    public var contentType: String
    public var body: Data

    public init(status: Int = 200, contentType: String = "text/html; charset=utf-8", body: Data) {
        self.status = status
        self.contentType = contentType
        self.body = body
    }

    public init(status: Int = 200, contentType: String = "text/plain; charset=utf-8", text: String) {
        self.init(status: status, contentType: contentType, body: Data(text.utf8))
    }

    public static func json<T: Encodable>(_ value: T, status: Int = 200) -> HTTPResponse {
        let data = (try? JSONEncoder().encode(value)) ?? Data("{}".utf8)
        return HTTPResponse(status: status, contentType: "application/json", body: data)
    }
}

