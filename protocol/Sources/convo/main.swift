import ConvoCLI
import Foundation

do {
    let (options, words) = try ConvoCLI.parse(Array(CommandLine.arguments.dropFirst()))
    for line in try await ConvoCLI(options: options).run(words) { print(line) }
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
