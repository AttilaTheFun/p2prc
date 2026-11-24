// A control: the plainest possible SwiftUI app with a two-column
// NavigationSplitView and an inspector, nothing else. Whatever this does
// out of the box (sidebar width on open, the X in the bar, resizing) is the
// platform's own behaviour, so Convo's split view can be compared against it.
import SwiftUI

@main
struct SplitInspectorLab: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .defaultSize(width: 960, height: 640)
    }
}

struct Item: Identifiable, Hashable {
    let id: Int
    var name: String { "Item \(id)" }
}

/// Knobs, each one thing Convo's split view does that this control does
/// not, so a difference can be switched on alone: LAB=balanced,constvis,
/// minwidth,fixedinsp,inset,geometry,notoggle,notoggle_sidebar,bigtitle,mountonly,xonly,xdelay,headertitle,clearbar,clearbar26,emptyclose,sidebartb,navitem,sidebarcompose,xhidden,xzero,xempty,xhiddenitem (comma-separated).
let knobs = Set((ProcessInfo.processInfo.environment["LAB"] ?? "").split(separator: ",").map(String.init))

struct ContentView: View {
    private let items = (1...8).map(Item.init)
    @State private var selection: Item?
    @State private var showsInspector = false
    @State private var visibility: NavigationSplitViewVisibility = .all

    var body: some View {
        split
            .frame(minWidth: knobs.contains("minwidth") ? 900 : nil, minHeight: knobs.contains("minwidth") ? 440 : nil)
    }

    @ViewBuilder private var split: some View {
        if knobs.contains("constvis") {
            NavigationSplitView(columnVisibility: .constant(.all)) { sidebar } detail: { detail }
                .modifier(Rest(showsInspector: $showsInspector, selection: selection))
        } else {
            NavigationSplitView { sidebar } detail: { detail }
                .modifier(Rest(showsInspector: $showsInspector, selection: selection))
        }
    }

    private var sidebar: some View {
            List(items, selection: $selection) { item in
                Text(item.name).tag(item)
            }
            .navigationTitle("Sidebar")
            .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 320)
            .modifier(SidebarToggle())
            // sidebartb: a toolbar on the sidebar whose items are all
            // conditional and absent (Convo's inbox on the Mac).
            .toolbar {
                if knobs.contains("sidebartb"), knobs.contains("never") {
                    ToolbarItem { Button("Never") {} }
                }
                // sidebarcompose: compose at the trailing end of the
                // sidebar's own bar section.
                if knobs.contains("sidebarcompose") {
                    ToolbarItem(placement: .primaryAction) {
                        Button("Compose", systemImage: "square.and.pencil") {}
                    }
                }
            }
    }

    @ViewBuilder private var detail: some View {
        detailColumn
            .toolbar {
                // navitem: a compose-like item at the leading end of the
                // content's bar, as Convo has.
                if knobs.contains("navitem") {
                    ToolbarItem(placement: .navigation) {
                        Button("Compose", systemImage: "square.and.pencil") {}
                    }
                }
            }
    }

    @ViewBuilder private var detailColumn: some View {
            if let selection, knobs.contains("headertitle") {
                DetailBody(name: selection.name)
                    .navigationTitle("")
                    .toolbar {
                        ToolbarItem {
                            Button("Info", systemImage: "info.circle") { showsInspector.toggle() }
                        }
                    }
                    .overlay(alignment: .top) {
                        Button(action: { showsInspector.toggle() }) {
                            ZStack(alignment: .top) {
                                HStack(spacing: 4) {
                                    Text(selection.name).font(.headline)
                                    Image(systemName: "chevron.compact.forward").font(.caption.weight(.heavy))
                                }
                                .padding(.leading, 12).padding(.trailing, 8).padding(.vertical, 5)
                                .background(Capsule().fill(.quaternary))
                                .padding(.top, 40 - 5)
                                Circle().fill(.gray).frame(width: 40, height: 40)
                                    .overlay(Text("I").foregroundColor(.white))
                            }
                        }
                        .buttonStyle(.plain)
                        // Up into the bar: the bar's buttons sit 6pt below
                        // the window's top; the content begins under the bar.
                        .offset(y: -(52 - 6))
                    }
                    .modifier(BarBackground())
            } else if let selection {
                DetailBody(name: selection.name)
                    .navigationTitle(selection.name)
                    .toolbar {
                        ToolbarItem(placement: .principal) {
                            if knobs.contains("bigtitle") {
                                // Convo's phone title: a 40pt avatar in front
                                // of a name pill, taller than the bar.
                                Button(action: { showsInspector.toggle() }) {
                                    ZStack(alignment: .top) {
                                        HStack(spacing: 4) {
                                            Text(selection.name).font(.headline)
                                            Image(systemName: "chevron.compact.forward").font(.caption.weight(.heavy))
                                        }
                                        .padding(.leading, 12).padding(.trailing, 8).padding(.vertical, 5)
                                        .background(Capsule().fill(.quaternary))
                                        .padding(.top, 40 - 5)
                                        Circle().fill(.gray).frame(width: 40, height: 40)
                                            .overlay(Text("I").foregroundColor(.white))
                                    }
                                    .offset(y: (40 - 5 + 27 - 28) / 2)
                                }
                                .buttonStyle(.plain)
                            } else {
                                Button(selection.name) { showsInspector.toggle() }
                            }
                        }
                        ToolbarItem {
                            Button("Info", systemImage: "info.circle") { showsInspector.toggle() }
                        }
                    }
            } else {
                Text("Select an item")
            }
    }
}

struct DetailBody: View {
    let name: String
    var body: some View {
        if knobs.contains("geometry") {
            GeometryReader { proxy in
                ScrollView {
                    Text("Detail for \(name)")
                        .frame(maxWidth: .infinity, minHeight: proxy.size.height, alignment: .bottom)
                }
            }
            .modifier(Inset())
        } else {
            Text("Detail for \(name)")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .modifier(Inset())
        }
    }
}

struct Inset: ViewModifier {
    func body(content: Content) -> some View {
        if knobs.contains("inset") {
            content.safeAreaInset(edge: .bottom) {
                TextField("Message", text: .constant(""))
                    .textFieldStyle(.roundedBorder)
                    .padding(12)
            }
        } else {
            content
        }
    }
}

struct Rest: ViewModifier {
    @Binding var showsInspector: Bool
    let selection: Item?
    @ViewBuilder func body(content: Content) -> some View {
        if knobs.contains("balanced") {
            content.navigationSplitViewStyle(.balanced).modifier(Toggle()).modifier(Inspected(showsInspector: $showsInspector, selection: selection))
        } else {
            content.modifier(Toggle()).modifier(Inspected(showsInspector: $showsInspector, selection: selection))
        }
    }
}

/// Apple's documented placement: on the sidebar's content.
struct SidebarToggle: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if knobs.contains("notoggle_sidebar") {
            content.toolbar(removing: .sidebarToggle)
        } else {
            content
        }
    }
}

/// clearbar: no material behind the window toolbar, so content drawn
/// up into it stays crisp.
struct BarBackground: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if knobs.contains("clearbar") {
            content.toolbarBackground(.hidden, for: .windowToolbar)
        } else if knobs.contains("clearbar26"), #available(macOS 26, *) {
            content.toolbarBackgroundVisibility(.hidden, for: .windowToolbar)
        } else {
            content
        }
    }
}

struct Toggle: ViewModifier {
    @ViewBuilder func body(content: Content) -> some View {
        if knobs.contains("notoggle") {
            content.toolbar(removing: .sidebarToggle)
        } else {
            content
        }
    }
}

struct Inspected: ViewModifier {
    @Binding var showsInspector: Bool
    let selection: Item?
    @State private var showsX = false
    func body(content: Content) -> some View {
        content
        .onChange(of: showsInspector) { _, on in
            if on { showsX = true } else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { showsX = showsInspector }
            }
        }
        .inspector(isPresented: $showsInspector) {
            // mountonly: content exists only while presented (Convo today).
            // xonly: content always mounted, the X item only while presented.
            // emptyclose: Messages' trick — the content becomes an empty
            // view the moment the pane closes, and the pane slides out empty.
            if knobs.contains("emptyclose"), !showsInspector {
                Color.clear.modifier(InspectorWidth())
            } else if !knobs.contains("mountonly") || showsInspector {
                NavigationStack {
                    List {
                        Text("Inspector for \(selection?.name ?? "nothing")")
                    }
                    .navigationTitle("Info")
                    .toolbar {
                        if knobs.contains("xhiddenitem"), #available(macOS 15, *) {
                            // The item's own hidden modifier.
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Close", systemImage: "xmark") { showsInspector = false }
                            }
                            .hidden(!showsInspector)
                        } else if knobs.contains("xzero") {
                            // Same item, zero-size content when closed.
                            ToolbarItem(placement: .cancellationAction) {
                                if showsInspector {
                                    Button("Close", systemImage: "xmark") { showsInspector = false }
                                } else {
                                    Color.clear.frame(width: 0, height: 0)
                                }
                            }
                        } else if knobs.contains("xempty") {
                            ToolbarItem(placement: .cancellationAction) {
                                if showsInspector {
                                    Button("Close", systemImage: "xmark") { showsInspector = false }
                                } else {
                                    EmptyView()
                                }
                            }
                        } else if knobs.contains("xhidden") {
                            // The item never leaves the set; it just hides.
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Close", systemImage: "xmark") { showsInspector = false }
                                    .opacity(showsInspector ? 1 : 0)
                                    .disabled(!showsInspector)
                            }
                        } else if knobs.contains("xdelay") ? showsX : (!knobs.contains("xonly") || showsInspector) {
                            ToolbarItem(placement: .cancellationAction) {
                                Button("Close", systemImage: "xmark") { showsInspector = false }
                            }
                        }
                    }
                }
                .modifier(InspectorWidth())
            }
        }
    }
}

struct InspectorWidth: ViewModifier {
    func body(content: Content) -> some View {
        if knobs.contains("fixedinsp") {
            content.inspectorColumnWidth(300)
        } else {
            content.inspectorColumnWidth(min: 260, ideal: 300, max: 360)
        }
    }
}

