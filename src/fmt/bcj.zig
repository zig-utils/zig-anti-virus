//! The x86 BCJ branch converter (decoding direction), as a reader. Encoders turn the relative
//! targets of E8 (call) and E9 (jmp) instructions into absolute addresses so they compress
//! better; decoding turns them back. Written from the .xz format description of the filter and
//! the public-domain reference behaviour (LZMA SDK, xz-embedded): a 3-bit history of recent E8/E9
//! bytes decides which candidates are real instructions, and a converted target is the 25-bit
//! sign-extended difference from the position after the instruction.
const std = @import("std");
const Io = std.Io;
const container = @import("../engine/container.zig");

const mask_to_allowed = [8]bool{ true, true, true, false, true, false, false, false };
const mask_to_bit_num = [8]u5{ 0, 1, 2, 2, 3, 3, 3, 3 };

fn testMsByte(b: u8) bool {
    return b == 0x00 or b == 0xff;
}

/// Convert `buf` in place, `pos` being the stream offset of `buf[0]`; returns how many leading
/// bytes are final (the last four may start an instruction that continues in the next block).
pub fn x86(buf: []u8, pos: u32, prev_mask_io: *u32) usize {
    if (buf.len <= 4) return 0;
    const size = buf.len - 4;
    var prev_pos: usize = std.math.maxInt(usize);
    var prev_mask = prev_mask_io.*;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        if (buf[i] & 0xfe != 0xe8) continue;
        const gap = i -% prev_pos;
        if (gap > 3) {
            prev_mask = 0;
        } else {
            prev_mask = (prev_mask << @intCast(gap - 1)) & 7;
            if (prev_mask != 0) {
                const b = buf[i + 4 - mask_to_bit_num[prev_mask]];
                if (!mask_to_allowed[prev_mask] or testMsByte(b)) {
                    prev_pos = i;
                    prev_mask = (prev_mask << 1) | 1;
                    continue;
                }
            }
        }
        prev_pos = i;
        if (testMsByte(buf[i + 4])) {
            var src = std.mem.readInt(u32, buf[i + 1 ..][0..4], .little);
            var dest: u32 = undefined;
            while (true) {
                dest = src -% (pos +% @as(u32, @truncate(i)) +% 5);
                if (prev_mask == 0) break;
                const j: u5 = mask_to_bit_num[prev_mask] * 8;
                const b: u8 = @truncate(dest >> (24 - j));
                if (!testMsByte(b)) break;
                src = dest ^ ((@as(u32, 1) << @intCast(32 - @as(u6, j))) - 1);
            }
            dest &= 0x01ffffff;
            dest |= 0 -% (dest & 0x01000000);
            std.mem.writeInt(u32, buf[i + 1 ..][0..4], dest, .little);
            i += 4;
        } else {
            prev_mask = (prev_mask << 1) | 1;
        }
    }
    const gap = i -% prev_pos;
    prev_mask_io.* = if (gap > 3) 0 else prev_mask << @intCast(gap - 1);
    return i;
}

/// A reader applying `x86` to everything read from `in`.
pub const X86Reader = struct {
    in: *Io.Reader,
    buf: []u8,
    /// `buf[0..done]` is converted and waiting to be read, `buf[done..len]` is not yet final.
    start: usize = 0,
    done: usize = 0,
    len: usize = 0,
    pos: u32 = 0,
    mask: u32 = 0,
    eof: bool = false,
    interface: Io.Reader,

    /// `work` is the conversion buffer (at least 64 bytes).
    pub fn init(in: *Io.Reader, work: []u8, buffer: []u8) X86Reader {
        return .{ .in = in, .buf = work, .interface = .{ .vtable = container.fillVTable(X86Reader), .buffer = buffer, .seek = 0, .end = 0 } };
    }

    pub fn fill(r: *X86Reader, dest: []u8) Io.Reader.Error!usize {
        while (r.start == r.done) {
            if (r.eof) {
                // The tail that never got four more bytes is passed on as it is.
                if (r.done == r.len) return 0;
                r.done = r.len;
                break;
            }
            // Keep the unconverted tail and read more after it.
            const tail = r.len - r.done;
            std.mem.copyForwards(u8, r.buf[0..tail], r.buf[r.done..r.len]);
            r.start = 0;
            r.done = 0;
            r.len = tail;
            while (r.len < r.buf.len) {
                const n = container.readSome(r.in, r.buf[r.len..]) catch |e| switch (e) {
                    error.EndOfStream => {
                        r.eof = true;
                        break;
                    },
                    error.ReadFailed => return error.ReadFailed,
                };
                r.len += n;
            }
            r.done = x86(r.buf[0..r.len], r.pos, &r.mask);
            r.pos +%= @truncate(r.done);
        }
        const n = @min(r.done - r.start, dest.len);
        @memcpy(dest[0..n], r.buf[r.start..][0..n]);
        r.start += n;
        return n;
    }
};

test "x86 BCJ turns absolute call and jmp targets back into relative ones" {
    // A call at 0 to +0x10, a jmp at 5 to -0x20, then a call whose operand's top byte is not
    // 00 or FF (not converted). The 7z fixtures check the filter against liblzma's encoder.
    const plain = [_]u8{ 0xe8, 0x10, 0x00, 0x00, 0x00, 0xe9, 0xe0, 0xff, 0xff, 0xff, 0xe8, 0x01, 0x02, 0x03, 0x04, 0x90, 0x90, 0x90, 0x90, 0x90 };
    // Encoding: absolute = relative + position after the instruction.
    var enc = plain;
    std.mem.writeInt(u32, enc[1..5], 0x10 + 5, .little);
    std.mem.writeInt(u32, enc[6..10], @bitCast(@as(i32, -0x20 + 10)), .little);
    var mask: u32 = 0;
    const done = x86(&enc, 0, &mask);
    try std.testing.expect(done >= 15);
    try std.testing.expectEqualSlices(u8, &plain, &enc);
}
