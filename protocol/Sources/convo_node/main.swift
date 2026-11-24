import ConvoNodeMain
import Foundation

// Unbuffered lines through FileHandle: containers read logs from a pipe,
// and libc's `stdout` is not concurrency-safe to touch under Swift 6.
func log(_ message: String) {
    FileHandle.standardOutput.write(Data("\(ISO8601DateFormatter().string(from: Date())) \(message)\n".utf8))
}
let arguments = Array(CommandLine.arguments.dropFirst())
do {
    let options = try NodeOptions.parse(arguments)
    let runtime = try NodeRuntime(options: options, log: log)
    runtime.start()
    while true { sleep(3600) }
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
