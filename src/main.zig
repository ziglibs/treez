const std = @import("std");
const treez = @import("treez.zig");

pub fn main() !void {
    const ziglang = try treez.Language.get("zig");

    var parser = try treez.Parser.init();
    defer parser.deinit();

    try parser.setLanguage(ziglang);

    const tree = try parser.parseString(null, "const abc = 123;");
    std.log.info("{s}", .{tree.getRootNode()});
}
