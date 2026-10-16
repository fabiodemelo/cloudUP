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
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.temporaryDirectory
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
        listed[parent]?[e.path] = e.version
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

/// The resolved server address of a domain, shared by all its requests.
actor ServerCache {
    private var url: URL?
    private var pending: Task<URL, Error>?

    /// The cached URL, or a freshly resolved one when there is none yet or the
    /// cached one is `stale` (a request to it just failed). Concurrent callers
    /// share one resolution.
    func get(replacing stale: URL?, resolve: @escaping @Sendable () async throws -> URL) async throws -> URL {
        if let u = url, u != stale { return u }
        url = nil
        if let p = pending { return try await p.value }
        let p = Task { try await resolve() }
        pending = p
        defer { pending = nil }
        let u = try await p.value
        url = u
        return u
    }
}

final class Dav: Sendable {
    let domain: String
    let session: URLSession
    private let server = ServerCache()
    private static let connectionLost: Set<URLError.Code> = [.cannotConnectToHost, .networkConnectionLost, .timedOut]

    init(domain: String) {
        self.domain = domain
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 120
        session = URLSession(configuration: cfg)
    }

    /// Server base URL. Cached: drives.json is only re-read (and the app
    /// started) after a request to `stale` showed that server is gone.
    private func base(replacing stale: URL? = nil) async throws -> URL {
        try await server.get(replacing: stale) { [self] in try await resolve() }
    }

    /// Find the server in drives.json; starts CloudUp in the background if it isn't running.
    private func resolve() async throws -> URL {
        if let u = await published() { return u }
        launchApp()
        for _ in 0..<30 {
            try await Task.sleep(nanoseconds: 500_000_000)
            if let u = await published() { return u }
        }
        throw DavError.unreachable
    }

    /// The published address, if it answers. A stale entry's port may belong
    /// to another process (or another mount, with another token) by now.
    private func published() async -> URL? {
        guard let info = driveInfo(domain), let url = URL(string: info.url) else { return nil }
        return await answers(url) ? url : nil
    }

    /// Whether `url` is the token root of a live CloudUp WebDAV server.
    private func answers(_ url: URL) async -> Bool {
        var r = URLRequest(url: url)
        r.httpMethod = "OPTIONS"
        r.timeoutInterval = 5
        guard let (_, resp) = try? await session.data(for: r), let h = resp as? HTTPURLResponse else { return false }
        return (200..<300).contains(h.statusCode) && h.value(forHTTPHeaderField: "DAV") != nil
    }

    private func launchApp() {
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: appBundleID) else { return }
        let cfg = NSWorkspace.OpenConfiguration()
        cfg.activates = false
        cfg.arguments = ["--login"]
        NSWorkspace.shared.openApplication(at: app, configuration: cfg) { _, _ in }
    }

    /// Run a request against the server. If it shows the cached address is
    /// dead (no connection, or a 404/502 while the token root doesn't answer
    /// either), resolve the server again and retry once.
    private func withServer<T>(_ op: (URL) async throws -> T) async throws -> T {
        let b = try await base()
        do {
            return try await op(b)
        } catch {
            guard await gone(b, after: error) else { throw Self.mapped(error) }
            do { return try await op(try await base(replacing: b)) } catch { throw Self.mapped(error) }
        }
    }

    private func gone(_ b: URL, after error: Error) async -> Bool {
        if let e = error as? URLError { return Self.connectionLost.contains(e.code) }
        switch error {
        // A request with another mount's token gets 404 (502 from dav-server).
        case DavError.notFound, DavError.status(502):
            let alive = await answers(b)
            return !alive
        default: return false
        }
    }

    private static func mapped(_ e: Error) -> Error {
        if let u = e as? URLError, connectionLost.contains(u.code) { return DavError.unreachable }
        return e
    }

    private func url(_ path: String, on base: URL) throws -> URL {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "?#;")
        let enc = path.split(separator: "/", omittingEmptySubsequences: true)
            .map { String($0).addingPercentEncoding(withAllowedCharacters: allowed) ?? String($0) }
            .joined(separator: "/")
        let b = base.absoluteString
        // A name that still doesn't form a valid URL fails this one request
        // instead of crashing the extension.
        guard let u = URL(string: (b.hasSuffix("/") ? b : b + "/") + enc) else { throw DavError.status(400) }
        return u
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

    private func request(_ method: String, _ path: String, on b: URL,
                         headers: [String: String] = [:], body: Data? = nil) async throws -> Data {
        var r = URLRequest(url: try url(path, on: b))
        r.httpMethod = method
        headers.forEach { r.setValue($1, forHTTPHeaderField: $0) }
        r.httpBody = body
        let (data, resp) = try await session.data(for: r)
        try check(resp)
        return data
    }

    func send(_ method: String, _ path: String, headers: [String: String] = [:], body: Data? = nil) async throws -> Data {
        try await withServer { b in try await request(method, path, on: b, headers: headers, body: body) }
    }

    func list(_ path: String, depth: Int) async throws -> [DavEntry] {
        let body = #"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:getetag/></D:prop></D:propfind>"#
        return try await withServer { b in
            let data = try await request("PROPFIND", path, on: b, headers: ["Depth": "\(depth)", "Content-Type": "text/xml"], body: Data(body.utf8))
            return PropfindParser.parse(data, basePath: b.path)
        }
    }

    func download(_ path: String) async throws -> URL {
        try await withServer { b in
            let (tmp, resp) = try await session.download(from: try url(path, on: b))
            do { try check(resp) } catch { try? FileManager.default.removeItem(at: tmp); throw error }
            let dest = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.moveItem(at: tmp, to: dest)
            return dest
        }
    }

    func upload(_ path: String, from file: URL?) async throws {
        try await withServer { b in
            var r = URLRequest(url: try url(path, on: b))
            r.httpMethod = "PUT"
            let (_, resp): (Data, URLResponse)
            if let file = file {
                (_, resp) = try await session.upload(for: r, fromFile: file)
            } else {
                (_, resp) = try await session.upload(for: r, from: Data())
            }
            try check(resp)
        }
    }

    func move(_ from: String, _ to: String) async throws {
        try await withServer { b in
            let dest = try url(to, on: b).absoluteString
            _ = try await request("MOVE", from, on: b, headers: ["Destination": dest, "Overwrite": "F"])
        }
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
            // Decode once: URL.path would already decode, and decoding again
            // turns a name like "100%25" into "100%".
            var p = URLComponents(string: href)?.percentEncodedPath ?? href
            if p == basePath || p.hasPrefix(basePath + "/") { p = String(p.dropFirst(basePath.count)) }
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
        // CloudUp has no cloud-side trash: deletes are permanent. The hidden
        // placeholder Location (it only affects Finder's labels) is empty.
        if container == .trashContainer || ext.domain.identifier.rawValue == "cloudup-placeholder" {
            observer.finishEnumerating(upTo: nil)
            return
        }
        Task {
            do {
                if container == .workingSet {
                    // Everything Finder has seen: the folders it opened and their children.
                    // A folder gone from the server is skipped; any other error
                    // fails the enumeration rather than report an empty set.
                    var items: [NSFileProviderItem] = []
                    for folder in ext.state.knownFolders().keys {
                        do {
                            items += try await ext.children(folder).map { ext.item($0) }
                        } catch DavError.notFound {
                            continue
                        }
                    }
                    observer.didEnumerate(items)
                    observer.finishEnumerating(upTo: nil)
                    return
                }
                guard let path = ext.state.path(for: container) else { throw NSFileProviderError(.noSuchItem) }
                let entries = try await ext.children(path)
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
                    let now = try await ext.children(folder)
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

/// Lets a completion handler run once: finishing and cancelling can race.
final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

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
        case DavError.status(507): return NSFileProviderError(.insufficientQuota)
        // Other client errors won't go away on retry: report them instead of
        // letting Finder retry forever as if the server were down.
        case DavError.status(let code) where (400..<500).contains(code) && code != 408 && code != 429:
            return NSError(domain: NSCocoaErrorDomain, code: NSFileWriteUnknownError)
        case let e as NSFileProviderError: return e
        // Errors raised on purpose (unsupported item, local file errors).
        case let e as NSError where e.domain == NSCocoaErrorDomain: return e
        default: return NSFileProviderError(.serverUnreachable)
        }
    }

    /// Run one File Provider request. `finish` gets the result or the mapped
    /// error exactly once, the returned Progress completes with it, and
    /// cancelling the Progress stops the work and reports NSUserCancelledError.
    private func perform<T>(_ work: @escaping () async throws -> T,
                            finish: @escaping (T?, Error?) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        let once = Once()
        let complete = { (value: T?, error: Error?) in
            guard once.claim() else { return }
            progress.completedUnitCount = progress.totalUnitCount
            finish(value, error)
        }
        let task = Task {
            do { complete(try await work(), nil) } catch { complete(nil, self.fpError(error)) }
        }
        progress.cancellationHandler = {
            task.cancel()
            complete(nil, NSError(domain: NSCocoaErrorDomain, code: NSUserCancelledError))
        }
        return progress
    }

    private func entry(_ path: String) async throws -> DavEntry {
        if path == "/" { return DavEntry(path: "/", isDir: true, size: 0, modified: nil, etag: "root") }
        guard let e = try await dav.list(path, depth: 0).first else { throw DavError.notFound }
        // Keep the path asked for, so the item keeps its identifier.
        return DavEntry(path: path, isDir: e.isDir, size: e.size, modified: e.modified, etag: e.etag)
    }

    /// A folder's direct children (the listing also holds the folder itself).
    func children(_ path: String) async throws -> [DavEntry] {
        try await dav.list(path, depth: 1).filter { $0.path != path && parentPath($0.path) == path }
    }

    func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        perform({ [self] () -> NSFileProviderItem in
            guard let path = state.path(for: identifier) else { throw NSFileProviderError(.noSuchItem) }
            return item(try await entry(path))
        }, finish: completionHandler)
    }

    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        perform({ [self] () -> (URL, NSFileProviderItem) in
            guard let path = state.path(for: itemIdentifier) else { throw NSFileProviderError(.noSuchItem) }
            let e = try await entry(path)
            let file = try await dav.download(path)
            return (file, item(e))
        }, finish: { r, error in completionHandler(r?.0, r?.1, error) })
    }

    func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents url: URL?,
                    options: NSFileProviderCreateItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        perform({ [self] () -> NSFileProviderItem in
            guard let parent = state.path(for: itemTemplate.parentItemIdentifier) else { throw NSFileProviderError(.noSuchItem) }
            let path = join(parent, itemTemplate.filename)
            if itemTemplate.contentType == .folder {
                do {
                    _ = try await dav.send("MKCOL", path)
                } catch DavError.status(405) {
                    // Already there (e.g. a retry after a lost connection): fine if it's a folder.
                    guard try await entry(path).isDir else { throw DavError.status(405) }
                }
            } else if itemTemplate.contentType == .symbolicLink {
                throw NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError)
            } else {
                try await dav.upload(path, from: url)
            }
            let e = try await entry(path)
            state.noteChild(e)
            return item(e)
        }, finish: { item, error in completionHandler(item, [], false, error) })
    }

    func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields, contents newContents: URL?,
                    options: NSFileProviderModifyItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        perform({ [self] () -> (NSFileProviderItem, NSFileProviderItemFields) in
            guard var path = state.path(for: item.itemIdentifier) else { throw NSFileProviderError(.noSuchItem) }
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
            return (self.item(e), unhandled.intersection([.contentModificationDate, .lastUsedDate, .tagData, .favoriteRank, .extendedAttributes, .fileSystemFlags, .creationDate]))
        }, finish: { r, error in completionHandler(r?.0, r?.1 ?? [], false, error) })
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion version: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [], request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        perform({ [self] in
            // Unknown or already gone: the deletion has happened (per the API contract).
            guard let path = state.path(for: identifier) else { return }
            do {
                let e: DavEntry
                do { e = try await entry(path) } catch DavError.notFound { state.forget(path); return }
                try await deleteTree(e, baseVersion: version, recursive: options.contains(.recursive))
            } catch DavError.forbidden {
                // Not allowed: have Finder put the item back instead of retrying forever.
                throw NSFileProviderError(.deletionRejected)
            }
            state.forget(path)
        }, finish: { (_: Void?, error) in completionHandler(error) })
    }

    /// Delete an item, and a folder's contents first (some backends only
    /// remove empty folders). Refuses (.deletionRejected) when the server has
    /// content Finder hasn't seen: a file changed since `baseVersion`, or,
    /// inside a folder, a file added or changed since Finder last listed it.
    /// Children already gone are skipped; if any other child can't be
    /// deleted, the folders above it are kept and .directoryNotEmpty reported.
    private func deleteTree(_ e: DavEntry, baseVersion: NSFileProviderItemVersion, recursive: Bool) async throws {
        let base = baseVersion.contentVersion
        // Folder dates move whenever their contents do, so only files are compared.
        if !e.isDir && base != NSFileProviderItemVersion.beforeFirstSyncComponent && base != Data(e.version.utf8) {
            throw NSFileProviderError(.deletionRejected)
        }
        var doomed: [DavEntry] = []   // children before their folder
        if e.isDir {
            doomed = try await tree(e.path)
            if !doomed.isEmpty && !recursive { throw NSFileProviderError(.directoryNotEmpty) }
            let seen = state.knownFolders()
            for c in doomed where !c.isDir {
                if let kids = seen[parentPath(c.path)], kids[c.path] != c.version {
                    throw NSFileProviderError(.deletionRejected)
                }
            }
        }
        var kept: Set<String> = []    // folders holding something that couldn't be deleted
        var failure: Error?
        for c in doomed + [e] {
            try Task.checkCancellation()
            if kept.contains(c.path) {
                if c.path != e.path { kept.insert(parentPath(c.path)) }
                continue
            }
            do {
                _ = try await dav.send("DELETE", c.path)
            } catch DavError.notFound {
                continue
            } catch DavError.unreachable {
                throw DavError.unreachable
            } catch {
                if c.path == e.path { throw error }
                failure = failure ?? error
                kept.insert(parentPath(c.path))
            }
        }
        if failure != nil { throw NSFileProviderError(.directoryNotEmpty) }
    }

    /// Everything under a folder, each folder after its contents.
    private func tree(_ dir: String) async throws -> [DavEntry] {
        let kids: [DavEntry]
        do { kids = try await children(dir) } catch DavError.notFound { return [] }
        var out: [DavEntry] = []
        for c in kids {
            if c.isDir { out += try await tree(c.path) }
            out.append(c)
        }
        return out
    }

    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        Enumerator(self, containerItemIdentifier)
    }
}
