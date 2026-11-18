//! Signatures compiled into every database, independent of any feed.
//!
//! The EICAR anti-malware test file (68 bytes, published by EICAR) is detected by hash here; its
//! variants with trailing whitespace are covered by the pattern rules in the Guardian rule pack.
const std = @import("std");
const ir = @import("ir.zig");

pub const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
pub const eicar_name = "Eicar-Test-Signature";

/// Hash rules for the built-in set, computed at compile time from the published test string.
pub fn rules() [3]ir.HashRule {
    var md5: [32]u8 = @splat(0);
    std.crypto.hash.Md5.hash(eicar, md5[0..16], .{});
    var sha1: [32]u8 = @splat(0);
    std.crypto.hash.Sha1.hash(eicar, sha1[0..20], .{});
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(eicar, &sha256, .{});
    return .{
        .{ .algo = .md5, .scope = .file, .digest = md5, .size = eicar.len, .name = eicar_name, .source = .guardian },
        .{ .algo = .sha1, .scope = .file, .digest = sha1, .size = eicar.len, .name = eicar_name, .source = .guardian },
        .{ .algo = .sha256, .scope = .file, .digest = sha256, .size = eicar.len, .name = eicar_name, .source = .guardian },
    };
}

test "EICAR digests match the published values" {
    const r = rules();
    try std.testing.expectEqualStrings("44d88612fea8a8f36de82e1278abb02f", &std.fmt.bytesToHex(r[0].digest[0..16].*, .lower));
    try std.testing.expectEqualStrings("3395856ce81f2b7382dee72602f798b642f14140", &std.fmt.bytesToHex(r[1].digest[0..20].*, .lower));
    try std.testing.expectEqualStrings("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", &std.fmt.bytesToHex(r[2].digest, .lower));
}
