const std = @import("std");
const treez = @import("treez.zig");

pub fn main() !void {
    const ziglang = try treez.Language.get("zig");

    var parser = try treez.Parser.init();
    defer parser.deinit();

    try parser.setLanguage(ziglang);
}
