import MessagesUI
import ConvoApp
import ConvoMLS
import SwiftUI
#if canImport(UIKit)
import UIKit
#endif
#if canImport(AppKit)
import AppKit
#endif
import Isomer

/// Convo's colours are MessagesUI's; these names keep the app's own views
/// (pairing, settings, the contact's details) reading the one theme.
enum Palette {
    private static let theme = MessagesTheme()
    static var accent: Color { theme.accent }
    static var text: Color { theme.text }
    static var secondaryText: Color { theme.secondaryText }
    static var ok: Color { theme.online }
    static var idle: Color { theme.idle }
    static var danger: Color { theme.danger }
}
