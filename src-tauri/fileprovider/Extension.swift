// CloudUp Finder extension (File Provider, replicated).
//
// Each connection the user mounts is a File Provider domain, shown by Finder
// as its own Location ("CloudUp - DM bucket"). The extension does no cloud
// work itself: CloudUp runs a small WebDAV server per mounted connection on
// 127.0.0.1 and publishes its address in the shared app-group container
// (drives.json). The extension is a WebDAV client of that server, so every
// provider CloudUp supports works here unchanged.

import AppKit
import FileProvider
import UniformTypeIdentifiers

let appGroup = "8V6DT796JV.net.cloudup"
let appBundleID = "net.cloudup.desktop"

// MARK: - Shared state

/// Address of a connection's server, written by CloudUp.
struct DriveInfo: Decodable {
    let name: String
    let url: String
}

func groupDir() -> URL? {
    FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
}

func driveInfo(_ domain: String) -> DriveInfo? {
    guard let dir = groupDir(),
          let data = try? Data(contentsOf: dir.appendingPathComponent("drives.json")),
          let all = try? JSONDecoder().decode([String: DriveInfo].self, from: data) else { return nil }
    return all[domain]
}

/// Per-domain bookkeeping, persisted in the extension's own container:
/// stable identifiers for paths (so renames keep an item's identity) and the
/// last listing of each folder Finder has opened (to report changes).
final class State {
    private let file: URL
    private let lock = NSLock()
    private var ids: [String: String] = [:]        // identifier -> path
    private var paths: [String: String] = [:]      // path -> identifier
    private var listed: [String: [String: String]] = [:] // folder -> child path -> version
    private(set) var anchor: Int = 1

    private struct Disk: Codable {
        var ids: [String: String]
        var listed: [String: [String: String]]
        var anchor: Int
    }

    init(domain: String) {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        file = base.appendingPathComponent("state-\(domain).json")
        if let data = try? Data(contentsOf: file), let d = try? JSONDecoder().decode(Disk.self, from: data) {
            ids = d.ids
            listed = d.listed
            anchor = d.anchor
            for (k, v) in ids { paths[v] = k }
        }
    }

    private func save() {
        let d = Disk(ids: ids, listed: listed, anchor: anchor)
        if let data = try? JSONEncoder().encode(d) { try? data.write(to: file, options: .atomic) }
    }

    func id(for path: String) -> NSFileProviderItemIdentifier {
        if path == "/" { return .rootContainer }
        lock.lock(); defer { lock.unlock() }
        if let id = paths[path] { return NSFileProviderItemIdentifier(id) }
        let id = UUID().uuidString
        ids[id] = path
        paths[path] = id
        save()
        return NSFileProviderItemIdentifier(id)
    }

    func path(for id: NSFileProviderItemIdentifier) -> String? {
        if id == .rootContainer { return "/" }
        lock.lock(); defer { lock.unlock() }
        return ids[id.rawValue]
    }

    /// Re-point an identifier (and everything under it) after a move/rename.
    func move(_ id: NSFileProviderItemIdentifier, from old: String, to new: String) {
        lock.lock(); defer { lock.unlock() }
        let prefix = old + "/"
        for (k, p) in ids where p == old || p.hasPrefix(prefix) {
            let np = new + p.dropFirst(old.count)
            ids[k] = np
            paths[p] = nil
            paths[np] = k
        }
        var moved: [String: [String: String]] = [:]
        for (folder, kids) in listed {
            let nf = (folder == old || folder.hasPrefix(prefix)) ? new + folder.dropFirst(old.count) : folder
            var nk: [String: String] = [:]
            for (c, v) in kids {
                nk[(c == old || c.hasPrefix(prefix)) ? new + c.dropFirst(old.count) : c] = v
            }
            moved[nf] = nk
        }
        listed = moved
        anchor += 1
        save()
    }

    func forget(_ path: String) {
        lock.lock(); defer { lock.unlock() }
        let prefix = path + "/"
        for (k, p) in ids where p == path || p.hasPrefix(prefix) {
            ids[k] = nil
            paths[p] = nil
        }
        listed = listed.filter { !($0.key == path || $0.key.hasPrefix(prefix)) }
        for (f, var kids) in listed where kids[path] != nil {
            kids[path] = nil
            listed[f] = kids
        }
        anchor += 1
        save()
    }

    func remember(folder: String, children: [DavEntry]) {
        lock.lock(); defer { lock.unlock() }
        listed[folder] = Dictionary(children.map { ($0.path, $0.version) }, uniquingKeysWith: { a, _ in a })
        save()
    }

    func noteChild(_ e: DavEntry) {
        lock.lock(); defer { lock.unlock() }
        let parent = parentPath(e.path)
        if listed[parent] != nil { listed[parent]![e.path] = e.version }
        anchor += 1
        save()
    }

    func knownFolders() -> [String: [String: String]] {
        lock.lock(); defer { lock.unlock() }
        return listed
    }

    func bumpAnchor() {
        lock.lock(); anchor += 1; save(); lock.unlock()
    }
}

func parentPath(_ p: String) -> String {
    guard let i = p.lastIndex(of: "/"), i != p.startIndex else { return "/" }
    return String(p[..<i])
}

func join(_ dir: String, _ name: String) -> String {
    dir == "/" ? "/" + name : dir + "/" + name
}

// MARK: - WebDAV client

struct DavEntry {
    let path: String
    let isDir: Bool
    let size: Int64
    let modified: Date?
    let etag: String?
    var name: String { String(path.split(separator: "/").last ?? "") }
    var version: String { etag ?? "\(size)-\(Int(modified?.timeIntervalSince1970 ?? 0))" }
}

enum DavError: Error {
    case unreachable, notFound, forbidden, status(Int)
}

final class Dav {
    let domain: String
    let session: URLSession

    init(domain: String) {
        self.domain = domain
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 120
        session = URLSession(configuration: cfg)
    }

    /// Server base URL; starts CloudUp in the background if it isn't running.
    func base() async throws -> URL {
        if let info = driveInfo(domain), let url = URL(string: info.url), await alive(url) { return url }
        launchApp()
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 500_000_000)
            if let info = driveInfo(domain), let url = URL(string: info.url), await alive(url) { return url }
        }
        throw DavError.unreachable
    }

    private func alive(_ url: URL) async -> Bool {
        var r = URLRequest(url: url)
        r.httpMethod = "OPTIONS"
        r.timeoutInterval = 3
        return (try? await session.data(for: r)) != nil
    }

    private func launchApp() {
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: appBundleID) else { return }
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.activates = false
        cfg.arguments = ["--login"]
        NSWorkspace.shared.openApplication(at: app, configuration: cfg) { _, _ in }
    }

    func url(_ path: String) async throws -> URL {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "?#;")
        let enc = path.split(separator: "/", omittingEmptySubsequences: true)
            .map { String($0).addingPercentEncoding(withAllowedCharacters: allowed) ?? String($0) }
            .joined(separator: "/")
        let b = try await base().absoluteString
        return URL(string: (b.hasSuffix("/") ? b : b + "/") + enc)!
    }

    private func check(_ resp: URLResponse) throws {
        guard let h = resp as? HTTPURLResponse else { return }
        switch h.statusCode {
        case 200..<300: return
        case 404: throw DavError.notFound
        case 401, 403: throw DavError.forbidden
        default: throw DavError.status(h.statusCode)
        }
    }

    func send(_ method: String, _ path: String, headers: [String: String] = [:], body: Data? = nil) async throws -> Data {
        var r = URLRequest(url: try await url(path))
        r.httpMethod = method
        headers.forEach { r.setValue($1, forHTTPHeaderField: $0) }
        r.httpBody = body
        do {
            let (data, resp) = try await session.data(for: r)
            try check(resp)
            return data
        } catch let e as URLError where [.cannotConnectToHost, .networkConnectionLost, .timedOut].contains(e.code) {
            throw DavError.unreachable
        }
    }

    func list(_ path: String, depth: Int) async throws -> [DavEntry] {
        let body = #"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:getetag/></D:prop></D:propfind>"#
        let data = try await send("PROPFIND", path, headers: ["Depth": "\(depth)", "Content-Type": "text/xml"], body: Data(body.utf8))
        let basePath = try await base().path
        return PropfindParser.parse(data, basePath: basePath)
    }

    func download(_ path: String) async throws -> URL {
        let (tmp, resp) = try await session.download(from: try await url(path))
        try check(resp)
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.moveItem(at: tmp, to: dest)
        return dest
    }

    func upload(_ path: String, from file: URL?) async throws {
        var r = URLRequest(url: try await url(path))
        r.httpMethod = "PUT"
        let (_, resp): (Data, URLResponse)
        if let file = file {
            (_, resp) = try await session.upload(for: r, fromFile: file)
        } else {
            (_, resp) = try await session.upload(for: r, from: Data())
        }
        try check(resp)
    }

    func move(_ from: String, _ to: String) async throws {
        let dest = try await url(to).absoluteString
        _ = try await send("MOVE", from, headers: ["Destination": dest, "Overwrite": "F"])
    }
}

/// Minimal multistatus parser (namespace-agnostic).
final class PropfindParser: NSObject, XMLParserDelegate {
    private var out: [DavEntry] = []
    private var text = ""
    private var href = "", isDir = false, size: Int64 = 0, modified: Date?, etag: String?
    private let basePath: String
    private static let httpDate: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "GMT")
        f.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return f
    }()

    init(basePath: String) { self.basePath = basePath.hasSuffix("/") ? String(basePath.dropLast()) : basePath }

    static func parse(_ data: Data, basePath: String) -> [DavEntry] {
        let p = PropfindParser(basePath: basePath)
        let x = XMLParser(data: data)
        x.shouldProcessNamespaces = true
        x.delegate = p
        x.parse()
        return p.out
    }

    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes: [String: String] = [:]) {
        text = ""
        switch name {
        case "response": href = ""; isDir = false; size = 0; modified = nil; etag = nil
        case "collection": isDir = true
        default: break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) { text += string }

    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        switch name {
        case "href": href = t
        case "getcontentlength": size = Int64(t) ?? 0
        case "getlastmodified": modified = Self.httpDate.date(from: t)
        case "getetag": etag = t.isEmpty ? nil : t
        case "response":
            var p = URL(string: href)?.path ?? href
            if p.hasPrefix(basePath) { p = String(p.dropFirst(basePath.count)) }
            p = p.removingPercentEncoding ?? p
            if p.count > 1 && p.hasSuffix("/") { p.removeLast() }
            if !p.hasPrefix("/") { p = "/" + p }
            out.append(DavEntry(path: p, isDir: isDir, size: size, modified: modified, etag: etag))
        default: break
        }
        text = ""
    }
}

// MARK: - Items

final class Item: NSObject, NSFileProviderItem {
    let itemIdentifier: NSFileProviderItemIdentifier
    let parentItemIdentifier: NSFileProviderItemIdentifier
    let filename: String
    let contentType: UTType
    let documentSize: NSNumber?
    let contentModificationDate: Date?
    let creationDate: Date?
    let itemVersion: NSFileProviderItemVersion
    let capabilities: NSFileProviderItemCapabilities

    init(_ e: DavEntry, state: State, domainName: String) {
        itemIdentifier = state.id(for: e.path)
        parentItemIdentifier = state.id(for: parentPath(e.path))
        filename = e.path == "/" ? domainName : e.name
        if e.isDir {
            contentType = .folder
        } else {
            let ext = (e.name as NSString).pathExtension
            contentType = UTType(filenameExtension: ext) ?? .data
        }
        documentSize = e.isDir ? nil : NSNumber(value: e.size)
        contentModificationDate = e.modified
        creationDate = e.modified
        let v = Data(e.version.utf8)
        itemVersion = NSFileProviderItemVersion(contentVersion: v, metadataVersion: Data((e.version + "|" + e.path).utf8))
        capabilities = e.isDir
            ? [.allowsReading, .allowsContentEnumerating, .allowsAddingSubItems, .allowsRenaming, .allowsReparenting, .allowsDeleting]
            : [.allowsReading, .allowsWriting, .allowsRenaming, .allowsReparenting, .allowsDeleting]
    }
}

// MARK: - Enumeration

final class Enumerator: NSObject, NSFileProviderEnumerator {
    let ext: FileProviderExtension
    let container: NSFileProviderItemIdentifier

    init(_ ext: FileProviderExtension, _ c: NSFileProviderItemIdentifier) {
        self.ext = ext
        container = c
    }

    func invalidate() {}

    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        // CloudUp has no cloud-side trash: deletes are permanent.
        if container == .trashContainer {
            observer.finishEnumerating(upTo: nil)
            return
        }
        Task {
            do {
                if container == .workingSet {
                    // Everything Finder has seen: the folders it opened and their children.
                    var items: [NSFileProviderItem] = []
                    for folder in ext.state.knownFolders().keys {
                        if let kids = try? await ext.dav.list(folder, depth: 1) {
                            items += kids.filter { $0.path != folder }.map { ext.item($0) }
                        }
                    }
                    observer.didEnumerate(items)
                    observer.finishEnumerating(upTo: nil)
                    return
                }
                guard let path = ext.state.path(for: container) else { throw NSFileProviderError(.noSuchItem) }
                let entries = try await ext.dav.list(path, depth: 1).filter { $0.path != path }
                ext.state.remember(folder: path, children: entries)
                observer.didEnumerate(entries.map { ext.item($0) })
                observer.finishEnumerating(upTo: nil)
            } catch {
                observer.finishEnumeratingWithError(ext.fpError(error))
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver, from anchor: NSFileProviderSyncAnchor) {
        Task {
            guard container == .workingSet else {
                observer.finishEnumeratingChanges(upTo: ext.anchor(), moreComing: false)
                return
            }
            // Re-list every folder Finder has opened; report what changed.
            var updated: [NSFileProviderItem] = []
            var deleted: [NSFileProviderItemIdentifier] = []
            for (folder, old) in ext.state.knownFolders() {
                do {
                    let now = try await ext.dav.list(folder, depth: 1).filter { $0.path != folder }
                    for e in now where old[e.path] != e.version { updated.append(ext.item(e)) }
                    let present = Set(now.map(\.path))
                    for p in old.keys where !present.contains(p) {
                        deleted.append(ext.state.id(for: p))
                        ext.state.forget(p)
                    }
                    ext.state.remember(folder: folder, children: now)
                } catch DavError.notFound {
                    deleted.append(ext.state.id(for: folder))
                    ext.state.forget(folder)
                } catch {
                    observer.finishEnumeratingWithError(ext.fpError(error))
                    return
                }
            }
            if !updated.isEmpty { observer.didUpdate(updated) }
            if !deleted.isEmpty { observer.didDeleteItems(withIdentifiers: deleted) }
            if !updated.isEmpty || !deleted.isEmpty { ext.state.bumpAnchor() }
            observer.finishEnumeratingChanges(upTo: ext.anchor(), moreComing: false)
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        completionHandler(ext.anchor())
    }
}

// MARK: - Extension

@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension {
    let domain: NSFileProviderDomain
    let dav: Dav
    let state: State

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        dav = Dav(domain: domain.identifier.rawValue)
        state = State(domain: domain.identifier.rawValue)
        super.init()
    }

    func invalidate() {}

    func anchor() -> NSFileProviderSyncAnchor { NSFileProviderSyncAnchor(Data("\(state.anchor)".utf8)) }

    func item(_ e: DavEntry) -> Item { Item(e, state: state, domainName: domain.displayName) }

    func fpError(_ e: Error) -> Error {
        switch e {
        case DavError.unreachable: return NSFileProviderError(.serverUnreachable)
        case DavError.notFound: return NSFileProviderError(.noSuchItem)
        case DavError.forbidden: return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError)
        case let e as NSFileProviderError: return e
        default: return NSFileProviderError(.serverUnreachable)
        }
    }

    private func entry(_ path: String) async throws -> DavEntry {
        if path == "/" { return DavEntry(path: "/", isDir: true, size: 0, modified: nil, etag: "root") }
        guard let e = try await dav.list(path, depth: 0).first else { throw DavError.notFound }
        return e
    }

    func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        Task {
            guard let path = state.path(for: identifier) else {
                completionHandler(nil, NSFileProviderError(.noSuchItem)); return
            }
            do { completionHandler(item(try await entry(path)), nil) } catch { completionHandler(nil, fpError(error)) }
        }
        return Progress()
    }

    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        Task {
            guard let path = state.path(for: itemIdentifier) else {
                completionHandler(nil, nil, NSFileProviderError(.noSuchItem)); return
            }
            do {
                let e = try await entry(path)
                let file = try await dav.download(path)
                progress.completedUnitCount = 1
                completionHandler(file, item(e), nil)
            } catch { completionHandler(nil, nil, fpError(error)) }
        }
        return progress
    }

    func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?,
                    options: NSFileProviderCreateItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        Task {
            guard let parent = state.path(for: itemTemplate.parentItemIdentifier) else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem)); return
            }
            let path = join(parent, itemTemplate.filename)
            do {
                if itemTemplate.contentType == .folder {
                    _ = try await dav.send("MKCOL", path)
                } else if itemTemplate.contentType == .symbolicLink {
                    throw NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError)
                } else {
                    try await dav.upload(path, from: url)
                }
                let e = try await entry(path)
                state.noteChild(e)
                completionHandler(item(e), [], false, nil)
            } catch { completionHandler(nil, [], false, fpError(error)) }
        }
        return Progress()
    }

    func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields, contents newContents: URL?,
                    options: NSFileProviderModifyItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        Task {
            guard var path = state.path(for: item.itemIdentifier) else {
                completionHandler(nil, [], false, NSFileProviderError(.noSuchItem)); return
            }
            do {
                if changedFields.contains(.filename) || changedFields.contains(.parentItemIdentifier) {
                    guard let parent = state.path(for: item.parentItemIdentifier) else { throw NSFileProviderError(.noSuchItem) }
                    let dest = join(parent, item.filename)
                    if dest != path {
                        try await dav.move(path, dest)
                        state.move(item.itemIdentifier, from: path, to: dest)
                        path = dest
                    }
                }
                if changedFields.contains(.contents), let file = newContents {
                    try await dav.upload(path, from: file)
                }
                let e = try await entry(path)
                state.noteChild(e)
                // Dates, tags etc. aren't stored remotely: accept them as-is.
                let unhandled = changedFields.subtracting([.filename, .parentItemIdentifier, .contents])
                completionHandler(self.item(e), unhandled.intersection([.contentModificationDate, .lastUsedDate, .tagData, .favoriteRank, .extendedAttributes, .fileSystemFlags, .creationDate]), false, nil)
            } catch { completionHandler(nil, [], false, fpError(error)) }
        }
        return Progress()
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        Task {
            guard let path = state.path(for: identifier) else { completionHandler(nil); return }
            do {
                // Folders: delete children first (some backends only remove empty folders).
                try await deleteTree(path)
                state.forget(path)
                completionHandler(nil)
            } catch DavError.notFound {
                state.forget(path)
                completionHandler(nil)
            } catch { completionHandler(fpError(error)) }
        }
        return Progress()
    }

    private func deleteTree(_ path: String) async throws {
        let e = try await entry(path)
        if e.isDir {
            for child in try await dav.list(path, depth: 1) where child.path != path {
                try await deleteTree(child.path)
            }
        }
        _ = try await dav.send("DELETE", path)
    }

    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        Enumerator(self, containerItemIdentifier)
    }
}
