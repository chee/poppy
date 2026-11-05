// Poppy — a small menu bar memory watcher for small-RAM Macs.
//
// Watches memory pressure, groups processes by the app they belong to, tracks
// which ones are growing and which apps you haven't touched in a while, and
// offers to quit them before the machine starts swapping itself to death.
//
// Build: ./build.sh     Report in the terminal: Poppy.app/Contents/MacOS/Poppy --report

import AppKit
import Darwin
import ServiceManagement
import UserNotifications

// MARK: - Formatting

func fmtBytes(_ b: UInt64) -> String {
    let mb = Double(b) / 1_048_576
    return mb >= 1000 ? String(format: "%.1f GB", mb / 1024) : String(format: "%.0f MB", mb)
}

func fmtSigned(_ b: Int64) -> String { (b >= 0 ? "+" : "−") + fmtBytes(b.magnitude) }

func fmtDuration(_ s: TimeInterval) -> String {
    let m = max(1, Int(s / 60))
    if m < 60 { return "\(m)m" }
    return m % 60 == 0 ? "\(m / 60)h" : "\(m / 60)h \(m % 60)m"
}

// MARK: - System-wide memory

enum Severity: Int, Comparable {
    case normal, warning, critical
    static func < (a: Severity, b: Severity) -> Bool { a.rawValue < b.rawValue }
    var label: String { ["Normal", "Warning", "Critical"][rawValue] }
}

func sysctlValue<T: BitwiseCopyable>(_ name: String, _ initial: T) -> T? {
    var v = initial
    var size = MemoryLayout<T>.size
    return sysctlbyname(name, &v, &size, nil, 0) == 0 ? v : nil
}

struct SystemMemory {
    var total: UInt64 = 0
    var available = 100            // kern.memorystatus_level: % of memory the kernel considers free
    var kernelPressure = Severity.normal
    var appMemory: UInt64 = 0
    var wired: UInt64 = 0
    var compressed: UInt64 = 0     // physical RAM occupied by the compressor
    var swapUsed: UInt64 = 0

    /// Kernel pressure level, bumped up if available memory is very low.
    var severity: Severity {
        var s = kernelPressure
        if available <= 8 { s = max(s, .critical) } else if available <= 15 { s = max(s, .warning) }
        return s
    }

    static func read() -> SystemMemory {
        var m = SystemMemory()
        m.total = sysctlValue("hw.memsize", UInt64(0)) ?? 0
        m.available = Int(sysctlValue("kern.memorystatus_level", Int32(100)) ?? 100)
        switch sysctlValue("kern.memorystatus_vm_pressure_level", Int32(1)) ?? 1 {
        case 4: m.kernelPressure = .critical
        case 2: m.kernelPressure = .warning
        default: m.kernelPressure = .normal
        }
        // POPPY_SIMULATE=warning|critical to try out the alerts without actually running out of RAM.
        switch ProcessInfo.processInfo.environment["POPPY_SIMULATE"] {
        case "warning": m.kernelPressure = .warning
        case "critical": m.kernelPressure = .critical
        default: break
        }
        var stats = vm_statistics64()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &stats) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        if kr == KERN_SUCCESS {
            let page = UInt64(getpagesize())
            m.appMemory = UInt64(stats.internal_page_count &- stats.purgeable_count) * page
            m.wired = UInt64(stats.wire_count) * page
            m.compressed = UInt64(stats.compressor_page_count) * page
        }
        if let swap = sysctlValue("vm.swapusage", xsw_usage()) { m.swapUsed = swap.xsu_used }
        return m
    }
}

// MARK: - Processes

struct Proc {
    let pid: pid_t
    let ppid: pid_t
    let start: UInt64   // start time, used to make sure a pid wasn't reused before killing it
    let name: String
    let detail: String  // what it's running and where, e.g. "vite · ~/soft/site"
    let path: String
    let footprint: UInt64
    var cpu: Double     // percent of one core since the last sample
}

private typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
private let responsiblePid: ResponsibleFn? = {
    // Private but long-standing libSystem call; it's what Activity Monitor uses to attribute XPC helpers.
    guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "responsibility_get_pid_responsible_for_pid") else { return nil }
    return unsafeBitCast(sym, to: ResponsibleFn.self)
}()

private let machToNanos: Double = {
    var tb = mach_timebase_info_data_t()
    mach_timebase_info(&tb)
    return Double(tb.numer) / Double(tb.denom)
}()

func tupleString<T>(_ t: T) -> String {
    withUnsafeBytes(of: t) { String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self) }
}

func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
    var info = proc_bsdinfo()
    let size = Int32(MemoryLayout<proc_bsdinfo>.size)
    return proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size ? info : nil
}

func outermostApp(_ path: String) -> String? {
    guard let r = path.range(of: ".app/") else { return nil }
    return String(path[..<r.lowerBound]) + ".app"
}

/// argv as the process currently reports it (processes that set their title, like `claude`, show up nicely).
func procArgs(_ pid: pid_t, _ buf: inout [UInt8]) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = buf.count
    guard sysctl(&mib, 3, &buf, &size, nil, 0) == 0, size > 4 else { return [] }
    let argc = Int(buf.withUnsafeBytes { $0.load(as: Int32.self) })
    var i = 4
    while i < size && buf[i] != 0 { i += 1 }   // exec path
    while i < size && buf[i] == 0 { i += 1 }   // padding
    var args: [String] = []
    while args.count < argc && i < size {
        let start = i
        while i < size && buf[i] != 0 { i += 1 }
        args.append(String(decoding: buf[start..<i], as: UTF8.self))
        i += 1
    }
    return args
}

func procCwd(_ pid: pid_t) -> String? {
    var info = proc_vnodepathinfo()
    let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
    guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
    let p = tupleString(info.pvi_cdir.vip_path)
    return p.isEmpty ? nil : p
}

let interpreters: Set<String> = ["node", "deno", "bun", "ruby", "java", "perl", "php", "sh", "bash", "zsh", "Python", "uv", "npx", "tsx"]

func normalize(_ path: String) -> [String] {
    var out: [String] = []
    for c in path.split(separator: "/") {
        if c == "." || c.isEmpty { continue }
        if c == "..", !out.isEmpty, out.last != ".." { out.removeLast() } else { out.append(String(c)) }
    }
    return out
}

/// "…/node_modules/.bin/../vite/bin/vite.js" → "vite", "/srv/app/index.js" → "app/index.js"
func scriptLabel(_ script: String) -> String {
    let comps = normalize(script)
    if let nm = comps.lastIndex(of: "node_modules") {
        var rest = comps[(nm + 1)...]
        if rest.first == ".bin" { rest = rest.dropFirst() }
        if let first = rest.first {
            return first.hasPrefix("@") && rest.count > 1 ? first + "/" + rest[rest.index(after: rest.startIndex)] : first
        }
    }
    guard let last = comps.last else { return script }
    let stem = (last as NSString).deletingPathExtension
    if ["index", "main", "cli", "server", "app", "__main__", "run"].contains(stem), comps.count > 1 {
        return comps[comps.count - 2] + "/" + last
    }
    return last
}

func abbreviateDir(_ dir: String) -> String {
    let home = NSHomeDirectory()
    if dir == home { return "~" }
    if dir == "/" { return "/" }
    let comps = normalize(dir)
    let tail = comps.suffix(2).joined(separator: "/")
    if dir.hasPrefix(home + "/") { return comps.count - normalize(home).count > 2 ? "~/…/" + tail : "~/" + tail }
    return comps.count > 2 ? "…/" + tail : dir
}

func looksLikeVersion(_ s: String) -> Bool { s.first?.isNumber ?? false }

/// A human name for the process and a short description of what it's doing.
func identify(pid: pid_t, path: String, bsdName: String, args: [String]) -> (name: String, detail: String) {
    var name = path.isEmpty ? bsdName : (path as NSString).lastPathComponent
    if let argv0 = args.first.map({ ($0 as NSString).lastPathComponent }), !argv0.isEmpty, looksLikeVersion(name) || name.isEmpty {
        name = argv0   // e.g. ~/.local/share/claude/versions/2.1.318 calls itself "claude"
    }
    if name.hasPrefix("python") || name.hasPrefix("Python") { name = "python" }
    var parts: [String] = []
    if interpreters.contains(name) || name == "python", let script = args.dropFirst().first(where: { !$0.hasPrefix("-") }) {
        parts.append(scriptLabel(script))
    }
    if outermostApp(path) == nil, !systemPrefixes.contains(where: { path.hasPrefix($0) }), let cwd = procCwd(pid), cwd != "/" {
        parts.append("in " + abbreviateDir(cwd))
    }
    return (name, parts.joined(separator: " · "))
}

let systemPrefixes = ["/System/Library/", "/System/Volumes/Preboot/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/", "/Library/Developer/CommandLineTools/"]
let neverTouch: Set<String> = ["loginwindow", "WindowServer", "launchd", "kernel_task", "Poppy", "Dock", "SystemUIServer", "Finder", "ControlCenter", "NotificationCenter"]

struct Group {
    let key: String
    let name: String
    let bundlePath: String?
    let app: NSRunningApplication?
    let isSystem: Bool
    var procs: [Proc] = []
    var footprint: UInt64 = 0
    var cpu: Double = 0

    var isProtected: Bool { neverTouch.contains(name) }
    var isAppGroup: Bool { bundlePath != nil }
}

// MARK: - Monitor

struct Suggestion {
    let group: Group
    let reasons: [String]
    let score: Double
}

final class Monitor {
    private(set) var system = SystemMemory()
    private(set) var groups: [Group] = []
    private(set) var frontmostKey: String?
    let startedAt = Date()
    private var lastCPU: [pid_t: UInt64] = [:]
    private var lastSampleNanos: UInt64 = 0
    private var history: [String: [(Date, UInt64)]] = [:]
    private var lastHistoryAt = Date.distantPast
    private var lastActive: [String: Date] = [:]
    private let uid = getuid()
    private var pathBuf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    private var argsBuf = [UInt8](repeating: 0, count: Int(sysctlValue("kern.argmax", Int32(262_144)) ?? 262_144))
    private var identities: [pid_t: (start: UInt64, path: String, name: String, detail: String)] = [:]

    private func path(of pid: pid_t) -> String {
        let n = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        return n > 0 ? String(cString: pathBuf) : ""
    }

    func sample() {
        system = SystemMemory.read()

        let now = DispatchTime.now().uptimeNanoseconds
        let dt = lastSampleNanos == 0 ? 0 : Double(now - lastSampleNanos)
        lastSampleNanos = now

        let count = proc_listallpids(nil, 0)
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let got = Int(proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size)))

        var apps: [String: NSRunningApplication] = [:]
        var appExecByPid: [pid_t: String] = [:]
        for a in NSWorkspace.shared.runningApplications {
            if let p = a.bundleURL?.path { apps[p] = a }
            // Chrome runs from a temporary "code sign clone"; this gives us its real location.
            if let e = a.executableURL?.path { appExecByPid[a.processIdentifier] = e }
        }

        var procs: [Proc] = []
        var cpuNow: [pid_t: UInt64] = [:]
        for pid in pids.prefix(max(0, got)) where pid > 0 {
            // Only our own processes: we can't read (or kill) anyone else's without root.
            guard let bsd = bsdInfo(pid), bsd.pbi_uid == uid else { continue }
            var ru = rusage_info_v4()
            let rc = withUnsafeMutablePointer(to: &ru) {
                $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V4, $0) }
            }
            guard rc == 0 else { continue }
            let cpuNanos = UInt64(Double(ru.ri_user_time + ru.ri_system_time) * machToNanos)
            cpuNow[pid] = cpuNanos
            var cpu = 0.0
            if dt > 0, let prev = lastCPU[pid], cpuNanos >= prev { cpu = Double(cpuNanos - prev) / dt * 100 }
            // Path/argv/cwd only change on exec, so look them up once per process.
            var id = identities[pid]
            if id == nil || id!.start != bsd.pbi_start_tvsec {
                let p = appExecByPid[pid] ?? path(of: pid)
                let (name, detail) = identify(pid: pid, path: p, bsdName: tupleString(bsd.pbi_name), args: procArgs(pid, &argsBuf))
                id = (bsd.pbi_start_tvsec, p, name, detail)
                identities[pid] = id
            }
            procs.append(Proc(pid: pid, ppid: pid_t(bsd.pbi_ppid), start: bsd.pbi_start_tvsec, name: id!.name,
                              detail: id!.detail, path: id!.path, footprint: ru.ri_phys_footprint, cpu: cpu))
        }
        lastCPU = cpuNow
        identities = identities.filter { cpuNow[$0.key] != nil }

        // Group helpers under the app they belong to.
        let pathByPid = Dictionary(procs.map { ($0.pid, $0.path) }, uniquingKeysWith: { a, _ in a })

        var byKey: [String: Group] = [:]
        for p in procs {
            var bundle = outermostApp(p.path)
            if bundle == nil, p.path.contains(".xpc/"), let resp = responsiblePid?(p.pid), resp > 0, resp != p.pid {
                // e.g. WebKit's WebContent processes belong to Safari / Mail / whoever spawned them
                bundle = outermostApp(pathByPid[resp] ?? path(of: resp))
            }
            let key = bundle.map { "app:" + $0 } ?? "proc:" + p.name
            if byKey[key] == nil {
                let name = bundle.map { b in apps[b]?.localizedName ?? ((b as NSString).lastPathComponent as NSString).deletingPathExtension } ?? p.name
                let where_ = bundle ?? p.path
                byKey[key] = Group(key: key, name: name, bundlePath: bundle, app: bundle.flatMap { apps[$0] },
                                   isSystem: systemPrefixes.contains { where_.hasPrefix($0) })
            }
            byKey[key]!.procs.append(p)
            byKey[key]!.footprint += p.footprint
            byKey[key]!.cpu += p.cpu
        }
        groups = byKey.values.map { g in
            var g = g
            g.procs.sort { $0.footprint > $1.footprint }
            return g
        }.sorted { $0.footprint > $1.footprint }

        // Remember when each app was last in front.
        let date = Date()
        frontmostKey = NSWorkspace.shared.frontmostApplication?.bundleURL.map { "app:" + $0.path }
        if let k = frontmostKey { lastActive[k] = date }

        // Footprint history every 30s, kept for 30 minutes.
        if date.timeIntervalSince(lastHistoryAt) >= 30 {
            lastHistoryAt = date
            var points = groups.map { ($0.key, $0.footprint) }
            for g in groups where !g.isAppGroup { points += g.procs.map { (Monitor.procKey($0), $0.footprint) } }
            let live = Set(points.map(\.0))
            history = history.filter { live.contains($0.key) }
            for (key, bytes) in points where bytes > 50 << 20 {
                var h = history[key, default: []]
                h.append((date, bytes))
                h.removeAll { date.timeIntervalSince($0.0) > 1800 }
                history[key] = h
            }
        }
    }

    /// Change in footprint over (up to) the last 10 minutes.
    func growth(_ g: Group) -> (bytes: Int64, over: TimeInterval)? {
        guard let h = history[g.key], let first = h.first(where: { Date().timeIntervalSince($0.0) <= 630 }) else { return nil }
        let over = Date().timeIntervalSince(first.0)
        guard over >= 90 else { return nil }
        return (Int64(g.footprint) - Int64(first.1), over)
    }

    func idleFor(_ g: Group) -> TimeInterval? {
        guard g.app != nil, g.key != frontmostKey else { return nil }
        // If we've never seen it in front, it's been idle at least since Poppy started.
        return Date().timeIntervalSince(lastActive[g.key] ?? startedAt)
    }

    static func procKey(_ p: Proc) -> String { "pid:\(p.pid):\(p.start)" }

    /// Apps are suggested as a whole; command-line tools one process at a time
    /// (you want to stop *that* vite server, not every node process).
    func candidates() -> [Group] {
        groups.flatMap { g -> [Group] in
            if g.isAppGroup || g.procs.count == 1 { return [g] }
            return g.procs.map { p in
                Group(key: Monitor.procKey(p), name: p.name, bundlePath: nil, app: nil, isSystem: g.isSystem,
                      procs: [p], footprint: p.footprint, cpu: p.cpu)
            }
        }
    }

    func suggestions(limit: Int = 5) -> [Suggestion] {
        var out: [Suggestion] = []
        for g in candidates() where !g.isProtected && !g.isSystem && g.footprint >= 150 << 20 {
            var score = Double(g.footprint)
            var reasons = [fmtBytes(g.footprint)]
            if !g.isAppGroup, let d = g.procs.first?.detail, !d.isEmpty { reasons.insert(d, at: 0) }
            if let gr = growth(g), gr.bytes > 100 << 20 {
                score += 2 * Double(gr.bytes)
                reasons.append("\(fmtSigned(gr.bytes)) in \(fmtDuration(gr.over))")
            }
            if g.key == frontmostKey {
                score *= 0.25
                reasons.append("in use now")
            } else if let idle = idleFor(g), idle >= 600 {
                score *= 1 + min(idle / 3600, 1)
                reasons.append(lastActive[g.key] == nil ? "unused since Poppy started (\(fmtDuration(idle)))" : "unused \(fmtDuration(idle))")
            }
            if g.cpu >= 30 { reasons.append(String(format: "busy (%.0f%% CPU)", g.cpu)) }
            else if !g.isAppGroup, g.cpu < 0.5 { reasons.append("idle") }
            out.append(Suggestion(group: g, reasons: reasons, score: score))
        }
        return Array(out.sorted { $0.score > $1.score }.prefix(limit))
    }

    func growers(limit: Int = 3) -> [(Group, Int64, TimeInterval)] {
        candidates().compactMap { g -> (Group, Int64, TimeInterval)? in
            guard let gr = growth(g), gr.bytes >= 150 << 20 else { return nil }
            return (g, gr.bytes, gr.over)
        }.sorted { $0.1 > $1.1 }.prefix(limit).map { $0 }
    }

    func summaryLines() -> [String] {
        let s = system
        return [
            "Pressure: \(s.severity.label) — \(s.available)% available",
            "App \(fmtBytes(s.appMemory)) · Wired \(fmtBytes(s.wired)) · Compressed \(fmtBytes(s.compressed)) · Swap \(fmtBytes(s.swapUsed)) · of \(fmtBytes(s.total))",
        ]
    }
}

// MARK: - Killing things

/// Signal a process, but only if the pid still refers to the same process we sampled.
@discardableResult
func signal(_ p: Proc, _ sig: Int32) -> Bool {
    guard let info = bsdInfo(p.pid), info.pbi_start_tvsec == p.start else { return false }
    return kill(p.pid, sig) == 0
}

func stop(_ g: Group, force: Bool) {
    if let app = g.app, !app.isTerminated {
        let ok = force ? app.forceTerminate() : app.terminate()
        if ok { return }
    }
    for p in g.procs { signal(p, force ? SIGKILL : SIGTERM) }
}

// MARK: - Notifications

final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    var onQuit: ((String) -> Void)?
    var onOpen: (() -> Void)?
    private var authorized: Bool?          // nil until macOS answers the permission request
    private var pending: (String, String, Group?)?

    func setup() {
        let c = UNUserNotificationCenter.current()
        c.delegate = self
        c.requestAuthorization(options: [.alert, .sound]) { ok, _ in
            DispatchQueue.main.async {
                self.authorized = ok
                if let (t, b, g) = self.pending { self.pending = nil; self.post(title: t, body: b, quit: g) }
            }
        }
    }

    func post(title: String, body: String, quit: Group?) {
        guard let authorized else { pending = (title, body, quit); return }
        guard authorized else {
            // Fallback when notifications aren't allowed for the app bundle.
            let esc = { (s: String) in s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") }
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            proc.arguments = ["-e", "display notification \"\(esc(body))\" with title \"\(esc(title))\""]
            try? proc.run()
            return
        }
        let c = UNUserNotificationCenter.current()
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if let g = quit {
            let action = UNNotificationAction(identifier: "quit", title: "Quit \(g.name)", options: [.destructive])
            c.setNotificationCategories([UNNotificationCategory(identifier: "suggest", actions: [action], intentIdentifiers: [])])
            content.categoryIdentifier = "suggest"
            content.userInfo = ["key": g.key]
        }
        c.add(UNNotificationRequest(identifier: "poppy-pressure", content: content, trigger: nil))
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .sound])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        let key = response.notification.request.content.userInfo["key"] as? String
        let action = response.actionIdentifier
        DispatchQueue.main.async {
            if action == "quit", let key { self.onQuit?(key) } else { self.onOpen?() }
        }
        done()
    }
}

// MARK: - Log

final class EventLog {
    let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Poppy.log")

    func write(_ lines: [String]) {
        if let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? UInt64, size > 5 << 20 {
            let old = url.deletingPathExtension().appendingPathExtension("old.log")
            try? FileManager.default.removeItem(at: old)
            try? FileManager.default.moveItem(at: url, to: old)
        }
        let stamp = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withInternetDateTime])
        let text = lines.enumerated().map { $0.offset == 0 ? "[\(stamp)] \($0.element)" : "    \($0.element)" }.joined(separator: "\n") + "\n"
        guard let data = text.data(using: .utf8) else { return }
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile(); h.write(data); try? h.close()
        } else {
            try? data.write(to: url)
        }
    }
}

// MARK: - Menu bar app

final class ActionBox: NSObject {
    let run: () -> Void
    init(_ run: @escaping () -> Void) { self.run = run }
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    let monitor = Monitor()
    let notifier = Notifier()
    let log = EventLog()
    var statusItem: NSStatusItem!
    var timer: Timer?
    var pressureSource: DispatchSourceMemoryPressure?
    var lastSeverity = Severity.normal
    var lastNotified = Date.distantPast
    var lastLogged = Date.distantPast

    func applicationDidFinishLaunching(_ note: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        let menu = NSMenu()
        menu.delegate = self
        menu.autoenablesItems = false
        statusItem.menu = menu

        notifier.onOpen = { [weak self] in self?.statusItem.button?.performClick(nil) }
        notifier.onQuit = { [weak self] key in
            guard let self, let g = self.monitor.candidates().first(where: { $0.key == key }) else { return }
            stop(g, force: false)
            self.resample(after: 2)
        }
        notifier.setup()

        // Wake immediately when the kernel signals pressure, not just on the timer.
        let src = DispatchSource.makeMemoryPressureSource(eventMask: [.normal, .warning, .critical], queue: .main)
        src.setEventHandler { [weak self] in self?.tick() }
        src.resume()
        pressureSource = src

        // Run at login by default — that's the point of a background watcher.
        if !UserDefaults.standard.bool(forKey: "didRegisterLogin") {
            try? SMAppService.mainApp.register()
            UserDefaults.standard.set(true, forKey: "didRegisterLogin")
        }

        tick()
    }

    func schedule() {
        timer?.invalidate()
        // Sample faster when things are getting tight.
        let interval: TimeInterval = monitor.system.severity == .normal ? 5 : 2
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in self?.tick() }
    }

    func resample(after seconds: TimeInterval) {
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) { [weak self] in self?.tick() }
    }

    func tick() {
        monitor.sample()
        updateButton()
        react()
        schedule()
    }

    func updateButton() {
        guard let button = statusItem.button else { return }
        let sev = monitor.system.severity
        let title = " \(100 - monitor.system.available)%"
        var image = NSImage(systemSymbolName: sev == .normal ? "memorychip" : "memorychip.fill", accessibilityDescription: "Memory")
        button.imagePosition = .imageLeading
        if sev == .normal {
            image?.isTemplate = true
            button.attributedTitle = NSAttributedString(string: title, attributes: [.font: NSFont.menuBarFont(ofSize: 0)])
        } else {
            // The menu bar ignores contentTintColor on template images, so bake the color in.
            let color = sev == .critical ? NSColor.systemRed : NSColor.systemOrange
            image = image?.withSymbolConfiguration(NSImage.SymbolConfiguration(paletteColors: [color]))
            image?.isTemplate = false
            button.attributedTitle = NSAttributedString(string: title, attributes: [
                .font: NSFont.menuBarFont(ofSize: 0), .foregroundColor: color])
        }
        button.image = image
        button.toolTip = "Poppy — memory in use (100 − kernel's available %)\n" + monitor.summaryLines().joined(separator: "\n")
    }

    func react() {
        let sev = monitor.system.severity
        let now = Date()
        defer { lastSeverity = sev }

        if sev != lastSeverity || (sev > .normal && now.timeIntervalSince(lastLogged) > 300) {
            lastLogged = now
            var lines = ["\(lastSeverity.label) → \(sev.label)"] + monitor.summaryLines()
            lines += monitor.groups.prefix(8).map { g in
                var s = "\(fmtBytes(g.footprint))  \(g.name) (\(g.procs.count))"
                if let gr = monitor.growth(g) { s += "  \(fmtSigned(gr.bytes)) in \(fmtDuration(gr.over))" }
                return s
            }
            log.write(lines)
        }

        guard sev > .normal else { return }
        let worse = sev > lastSeverity && now.timeIntervalSince(lastNotified) > 60
        let stillBad = now.timeIntervalSince(lastNotified) > (sev == .critical ? 300 : 900)
        guard worse || stillBad else { return }
        lastNotified = now

        let title = sev == .critical ? "Memory is critical (\(monitor.system.available)% left)" : "Memory is getting tight (\(monitor.system.available)% left)"
        let top = monitor.suggestions(limit: 2)
        var body = "Swap \(fmtBytes(monitor.system.swapUsed)), compressed \(fmtBytes(monitor.system.compressed))."
        if let first = top.first {
            body = "\(first.group.name): " + first.reasons.joined(separator: ", ") + "."
            if top.count > 1 { body += " Also \(top[1].group.name) (\(fmtBytes(top[1].group.footprint)))." }
        }
        notifier.post(title: title, body: body, quit: top.first?.group)
    }

    // MARK: Menu

    func menuNeedsUpdate(_ menu: NSMenu) {
        monitor.sample()
        updateButton()
        menu.removeAllItems()

        let s = monitor.system
        let dot = ["🟢", "🟠", "🔴"][s.severity.rawValue]
        menu.addItem(label("\(dot) Memory pressure: \(s.severity.label) — \(s.available)% available"))
        menu.addItem(label("App \(fmtBytes(s.appMemory)) · Wired \(fmtBytes(s.wired)) · Compressed \(fmtBytes(s.compressed)) · Swap \(fmtBytes(s.swapUsed))", secondary: true))

        let suggestions = monitor.suggestions()
        menu.addItem(.separator())
        menu.addItem(header("Could quit"))
        if suggestions.isEmpty {
            menu.addItem(label("Nothing big worth quitting", secondary: true))
        }
        for sug in suggestions {
            menu.addItem(groupItem(sug.group, detail: sug.reasons.joined(separator: " · ")))
        }

        let growers = monitor.growers()
        if !growers.isEmpty {
            menu.addItem(.separator())
            menu.addItem(header("Growing"))
            for (g, bytes, over) in growers {
                menu.addItem(groupItem(g, detail: "\(fmtSigned(bytes)) in \(fmtDuration(over)) · now \(fmtBytes(g.footprint))"))
            }
        }

        menu.addItem(.separator())
        let all = NSMenuItem(title: "Everything (yours)", action: nil, keyEquivalent: "")
        let allMenu = NSMenu()
        allMenu.autoenablesItems = false
        for g in monitor.groups.prefix(30) {
            var detail = fmtBytes(g.footprint)
            if g.procs.count > 1 { detail += " · \(g.procs.count) procs" }
            if g.cpu >= 5 { detail += String(format: " · %.0f%% CPU", g.cpu) }
            if g.isSystem { detail += " · system" }
            allMenu.addItem(groupItem(g, detail: detail))
        }
        all.submenu = allMenu
        menu.addItem(all)

        menu.addItem(.separator())
        menu.addItem(action("Open Activity Monitor") {
            NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Activity Monitor.app"))
        })
        menu.addItem(action("Show Log") { [weak self] in
            guard let self else { return }
            if !FileManager.default.fileExists(atPath: self.log.url.path) { self.log.write(["Log started"] + self.monitor.summaryLines()) }
            NSWorkspace.shared.open(self.log.url)
        })
        let login = action("Launch at Login") {
            let svc = SMAppService.mainApp
            if svc.status == .enabled { try? svc.unregister() } else { try? svc.register() }
        }
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(login)
        menu.addItem(.separator())
        menu.addItem(action("Quit Poppy") { NSApp.terminate(nil) })
    }

    func groupItem(_ g: Group, detail: String) -> NSMenuItem {
        let item = NSMenuItem(title: g.name, action: nil, keyEquivalent: "")
        item.attributedTitle = twoTone(g.name, detail)
        item.image = icon(for: g)
        let sub = NSMenu()
        sub.autoenablesItems = false

        if g.isProtected {
            sub.addItem(label("Poppy won't touch this one — the system needs it", secondary: true))
        } else {
            if g.isSystem { sub.addItem(label("System process — macOS will probably restart it", secondary: true)) }
            let quitTitle = g.app != nil ? "Quit \(g.name)" : (g.procs.count > 1 ? "Stop all \(g.procs.count) “\(g.name)” processes" : "Stop \(g.name)")
            sub.addItem(action(quitTitle) { [weak self] in stop(g, force: false); self?.resample(after: 2) })
            let force = action("Force " + quitTitle.prefix(1).lowercased() + quitTitle.dropFirst() + "…") { [weak self] in
                guard self?.confirmForce(g) == true else { return }
                stop(g, force: true)
                self?.resample(after: 1)
            }
            force.isAlternate = true
            force.keyEquivalentModifierMask = .option
            sub.addItem(force)
        }

        if !g.isProtected {
            sub.addItem(.separator())
            sub.addItem(header(g.procs.count > 1 ? "Processes — click to stop one (⌥ to force)" : "Process — click to stop (⌥ to force)"))
            for p in g.procs.prefix(15) {
                var detail = "\(fmtBytes(p.footprint)) · pid \(p.pid)"
                if !p.detail.isEmpty { detail = p.detail + " · " + detail }
                if p.cpu >= 5 { detail += String(format: " · %.0f%% CPU", p.cpu) }
                let pi = action("") { [weak self] in signal(p, SIGTERM); self?.resample(after: 1.5) }
                pi.attributedTitle = twoTone(p.name, detail)
                sub.addItem(pi)
                let pk = action("") { [weak self] in signal(p, SIGKILL); self?.resample(after: 1) }
                pk.attributedTitle = twoTone("Force kill \(p.name)", detail)
                pk.isAlternate = true
                pk.keyEquivalentModifierMask = .option
                sub.addItem(pk)
            }
            if g.procs.count > 15 { sub.addItem(label("…and \(g.procs.count - 15) more", secondary: true)) }
        }
        if let b = g.bundlePath {
            sub.addItem(.separator())
            sub.addItem(action("Show in Finder") { NSWorkspace.shared.selectFile(b, inFileViewerRootedAtPath: "") })
        }
        item.submenu = sub
        return item
    }

    func confirmForce(_ g: Group) -> Bool {
        guard g.app != nil else { return true }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.messageText = "Force quit \(g.name)?"
        alert.informativeText = "Unsaved work in \(g.name) will be lost. It's using \(fmtBytes(g.footprint))."
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Force Quit")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    func icon(for g: Group) -> NSImage? {
        let img: NSImage?
        if let app = g.app { img = app.icon }
        else if let b = g.bundlePath { img = NSWorkspace.shared.icon(forFile: b) }
        else { img = NSImage(systemSymbolName: g.isSystem ? "gearshape" : "terminal", accessibilityDescription: nil) }
        img?.size = NSSize(width: 16, height: 16)
        return img
    }

    // MARK: Menu helpers

    @objc func runAction(_ sender: NSMenuItem) { (sender.representedObject as? ActionBox)?.run() }

    func action(_ title: String, _ run: @escaping () -> Void) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: #selector(runAction(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = ActionBox(run)
        return item
    }

    func label(_ text: String, secondary: Bool = false) -> NSMenuItem {
        let item = NSMenuItem(title: text, action: nil, keyEquivalent: "")
        item.isEnabled = false
        if secondary {
            item.attributedTitle = NSAttributedString(string: text, attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize), .foregroundColor: NSColor.secondaryLabelColor])
        }
        return item
    }

    func header(_ text: String) -> NSMenuItem {
        if #available(macOS 14.0, *) { return NSMenuItem.sectionHeader(title: text) }
        return label(text.uppercased(), secondary: true)
    }

    func twoTone(_ main: String, _ detail: String) -> NSAttributedString {
        let s = NSMutableAttributedString(string: main, attributes: [.font: NSFont.menuFont(ofSize: 0)])
        s.append(NSAttributedString(string: "   " + detail, attributes: [
            .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize), .foregroundColor: NSColor.secondaryLabelColor]))
        return s
    }
}

// MARK: - Terminal report

func printReport(verbose: Bool) {
    let m = Monitor()
    m.sample()
    Thread.sleep(forTimeInterval: 1)   // second sample so CPU % means something
    m.sample()
    m.summaryLines().forEach { print($0) }
    print("\nCould quit:")
    let sugs = m.suggestions()
    if sugs.isEmpty { print("  (nothing big)") }
    for s in sugs { print("  \(s.group.name) — \(s.reasons.joined(separator: ", "))") }
    print("\nBiggest (your processes, grouped by app):")
    for g in m.groups.prefix(15) {
        let tag = g.isProtected ? " [protected]" : g.isSystem ? " [system]" : ""
        print(String(format: "  %9@  %5.1f%% CPU  %3d proc  %@%@", fmtBytes(g.footprint) as NSString, g.cpu, g.procs.count, g.name as NSString, tag as NSString))
        if verbose {
            for p in g.procs.prefix(6) {
                print("               \(fmtBytes(p.footprint).padding(toLength: 9, withPad: " ", startingAt: 0)) \(p.pid)  \(p.name)  \(p.detail.isEmpty ? p.path : p.detail)")
            }
        }
    }
}

// MARK: - Main

if CommandLine.arguments.contains("--report") {
    printReport(verbose: CommandLine.arguments.contains("-v"))
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
