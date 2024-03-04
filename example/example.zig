const std = @import("std");
const treez = @import("../treez.zig");

const log = std.log.scoped(.treesitter_ast)

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const ziglang = try treez.Language.get("zig");

    var parser = try treez.Parser.create();
    defer parser.destroy();

    try parser.setLanguage(ziglang);
    // parser.useStandardLogger();

    const inp = @embedFile("example.zig");
    const tree = try parser.parseString(null, inp);
    defer tree.destroy();

    const query = try treez.Query.create(ziglang,
        \\(identifier) @id
    );
    defer query.destroy();

    var pv = try treez.CursorWithValidation.init(allocator, query);

    const cursor = try treez.Query.Cursor.create();
    defer cursor.destroy();

    cursor.execute(query, tree.getRootNode());

    while (pv.nextCapture(inp, cursor)) |capture| {
        const node = capture.node;
        log.info("{s}", .{inp[node.getStartByte()..node.getEndByte()]});
    }
}
