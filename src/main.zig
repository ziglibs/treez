const std = @import("std");
const treez = @import("treez.zig");

pub fn main() !void {
    const ziglang = try treez.Language.get("zig");

    var parser = try treez.Parser.init();
    defer parser.deinit();

    try parser.setLanguage(ziglang);

    const inp = @embedFile("main.zig");
    const tree = try parser.parseString(null, inp);
    defer tree.deinit();

    const query = try treez.Query.init(ziglang,
        \\[
        \\  function_call: (IDENTIFIER)
        \\  function: (IDENTIFIER)
        \\] @id
    );
    defer query.deinit();

    const cursor = try treez.QueryCursor.init();
    defer cursor.deinit();

    cursor.execute(query, tree.getRootNode());

    while (cursor.getNextCapture()) |match| {
        for (match.captureSlice()) |capture| {
            const node = treez.Node{ .raw = capture.node };
            std.log.info("{s}", .{inp[node.getStartByte()..node.getEndByte()]});
        }
    }
}
