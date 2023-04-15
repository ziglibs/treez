pub const c = @import("c.zig");
pub const std = @import("std");

pub const Symbol = c.Symbol;
pub const FieldId = c.FieldId;

pub const Point = c.Point;
pub const Logger = c.Logger;
pub const Range = c.Range;
pub const Input = c.Input;
pub const InputEdit = c.InputEdit;
pub const InputEncoding = c.InputEncoding;

pub const Language = struct {
    handle: *c.Language,

    pub const GetError = error{Unknown};
    pub fn get(comptime language_name: []const u8) GetError!Language {
        return .{
            .handle = @extern(fn () callconv(.C) ?*c.Language, .{
                .name = std.fmt.comptimePrint("tree_sitter_{s}", .{language_name}),
            })() orelse return error.Unknown,
        };
    }
};

pub const Parser = struct {
    handle: *c.Parser,

    pub const InitError = error{Unknown};
    pub fn init() InitError!Parser {
        return .{
            .handle = c.ts_parser_new() orelse return error.Unknown,
        };
    }

    pub fn deinit(parser: Parser) void {
        c.ts_parser_delete(parser.handle);
    }

    pub const SetLanguageError = error{VersionMismatch};
    pub fn setLanguage(parser: Parser, language: Language) SetLanguageError!void {
        if (!c.ts_parser_set_language(parser.handle, language.handle))
            return error.VersionMismatch;
    }

    pub fn getLanguage(parser: Parser) ?Language {
        return if (c.ts_parser_language(parser.handle)) |handle|
            .{ .handle = handle }
        else
            null;
    }

    pub const SetIncludedRangesError = error{Unknown};
    pub fn setIncludedRanges(parser: Parser, ranges: []const Range) void {
        if (!c.ts_parser_set_included_ranges(parser.handle, ranges.ptr, @intCast(u32, ranges.len)))
            return error.Unknown;
    }

    pub fn getIncludedRanges(parser: Parser) []const Range {
        var length: u32 = 0;
        return c.ts_parser_included_ranges(parser.handle, &length)[0..length];
    }

    pub const ParseError = error{ NoLanguage, Unknown };
    pub fn parse(parser: Parser, old_tree: ?Tree, input: Input) ParseError!Tree {
        return if (c.ts_parser_parse(parser.handle, if (old_tree) old_tree.handle else null, input)) |tree|
            .{ .handle = tree }
        else
            (if (parser.getLanguage()) |_|
                error.Unknown
            else
                error.NoLanguage);
    }

    pub fn parseString(parser: Parser, old_tree: ?Tree, string: []const u8) ParseError!Tree {
        return if (c.ts_parser_parse_string(parser.handle, if (old_tree) old_tree.handle else null, string.ptr, @intCast(u32, string.len))) |tree|
            .{ .handle = tree }
        else
            (if (parser.getLanguage()) |_|
                error.Unknown
            else
                error.NoLanguage);
    }

    pub fn parseStringWithEncoding(parser: Parser, old_tree: ?Tree, string: []const u8, encoding: InputEncoding) ParseError!Tree {
        return if (c.ts_parser_parse_string(parser.handle, if (old_tree) old_tree.handle else null, string.ptr, @intCast(u32, string.len), encoding)) |tree|
            .{ .handle = tree }
        else
            (if (parser.getLanguage()) |_|
                error.Unknown
            else
                error.NoLanguage);
    }

    pub fn reset(parser: Parser) void {
        c.ts_parser_reset(parser.handle);
    }

    pub fn setTimeout(parser: Parser, microseconds: u64) void {
        c.ts_parser_set_timeout_micros(parser.handle, microseconds);
    }

    pub fn getTimeout(parser: Parser) u64 {
        return c.ts_parser_timeout_micros(parser.handle);
    }

    pub fn setCancellationFlag(parser: Parser, flag: ?*const usize) void {
        c.ts_parser_set_cancellation_flag(parser.handle, flag);
    }

    pub fn getCancellationFlag(parser: Parser) ?*const usize {
        return c.ts_parser_cancellation_flag(parser.handle);
    }

    pub fn setLogger(parser: Parser, logger: Logger) void {
        c.ts_parser_set_logger(parser.handle, logger);
    }

    pub fn getLogger(parser: Parser) Logger {
        return c.ts_parser_logger(parser.handle);
    }

    pub fn printDotGraphs(parser: Parser, file: std.fs.File) void {
        c.ts_parser_print_dot_graphs(parser.handle, file.handle);
    }
};

pub const Tree = struct {
    handle: *c.Tree,

    pub const DupeError = error{Unknown};
    pub fn dupe(tree: Tree) DupeError!Tree {
        return .{ .handle = c.ts_tree_copy(tree.handle) orelse return error.Unknown };
    }

    pub fn deinit(tree: Tree) void {
        c.ts_tree_delete(tree.handle);
    }

    pub fn getRootNode(tree: Tree) Node {
        return .{ .raw = c.ts_tree_root_node(tree.handle) };
    }

    pub fn getRootNodeWithOffset(tree: Tree, offset_bytes: u32, offset_point: Point) Node {
        return .{ .raw = c.ts_tree_root_node_with_offset(tree.handle, offset_bytes, offset_point) };
    }

    pub fn getLanguage(tree: Tree) Language {
        return .{ .handle = c.ts_tree_language(tree.handle).? };
    }

    pub fn getIncludedRanges(tree: Tree) []const Range {
        var length: u32 = 0;
        return c.ts_tree_included_ranges(tree.handle, &length)[0..length];
    }

    /// Apply a text diff to the tree
    pub fn edit(tree: Tree, the_edit: *const InputEdit) void {
        c.ts_tree_edit(tree.handle, the_edit);
    }

    pub fn getChangedRanges(old: Tree, new: Tree) []const Range {
        var length: u32 = 0;
        return c.ts_tree_get_changed_ranges(old.handle, new.handle, &length)[0..length];
    }

    pub fn printDotGraph(tree: Tree, file: std.fs.File) void {
        c.ts_tree_print_dot_graph(tree.handle, file.handle);
    }
};

pub const Node = struct {
    raw: c.Node,

    pub const ChildIterator = struct {
        node: Node,
        index: u32 = 0,

        pub fn next(iterator: ChildIterator) ?Node {
            defer iterator.index += 1;

            var maybe_child = iterator.node.getChild(iterator.index);
            return if (maybe_child.isNull())
                null
            else
                maybe_child;
        }
    };

    pub const NamedChildIterator = struct {
        node: Node,
        index: u32 = 0,

        pub fn next(iterator: NamedChildIterator) ?Node {
            defer iterator.index += 1;

            var maybe_child = iterator.node.getNamedChild(iterator.index);
            return if (maybe_child.isNull())
                null
            else
                maybe_child;
        }
    };

    pub fn getTree(node: Node) Tree {
        return .{ .handle = node.raw.tree.? };
    }

    pub fn getType(node: Node) []const u8 {
        return std.mem.span(c.ts_node_type(node.raw));
    }

    pub fn getSymbol(node: Node) Symbol {
        return c.ts_node_symbol(node.raw);
    }

    pub fn getStartByte(node: Node) u32 {
        return c.ts_node_start_byte(node.raw);
    }

    pub fn getStartPoint(node: Node) Point {
        return c.ts_node_start_point(node.raw);
    }

    pub fn getEndByte(node: Node) u32 {
        return c.ts_node_end_byte(node.raw);
    }

    pub fn getEndPoint(node: Node) Point {
        return c.ts_node_end_point(node.raw);
    }

    /// Caller must call `freeSExpressionString` when done
    pub fn asSExpressionString(node: Node) []const u8 {
        return std.mem.span(c.ts_node_string(node.raw));
    }

    pub fn freeSExpressionString(str: []const u8) void {
        std.heap.c_allocator.free(str);
    }

    pub fn format(node: Node, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;

        const str = node.asSExpressionString();
        try writer.print("Node({s})", .{str});
        defer node.freeSExpressionString(str);
    }

    pub fn isNull(node: Node) bool {
        return c.ts_node_is_null(node.raw);
    }

    pub fn isNamed(node: Node) bool {
        return c.ts_node_is_named(node.raw);
    }

    pub fn isMissing(node: Node) bool {
        return c.ts_node_is_missing(node.raw);
    }

    pub fn isExtra(node: Node) bool {
        return c.ts_node_is_extra(node.raw);
    }

    pub fn hasChanges(node: Node) bool {
        return c.ts_node_has_changes(node.raw);
    }

    pub fn hasError(node: Node) bool {
        return c.ts_node_has_error(node.raw);
    }

    /// Remember to check with isNull (root)
    pub fn getParent(node: Node) Node {
        return .{ .raw = c.ts_node_parent(node.raw) };
    }

    /// Remember to check with isNull
    pub fn getChild(node: Node, child_index: u32) Node {
        return .{ .raw = c.ts_node_child(node.raw, child_index) };
    }

    pub fn childIterator(node: Node) ChildIterator {
        return ChildIterator{ .node = node };
    }

    pub fn getFieldNameForChild(node: Node, child_index: u32) ?[]const u8 {
        return std.mem.span(c.ts_node_field_name_for_child(node.raw, child_index) orelse return null);
    }

    pub fn getChildCount(node: Node) u32 {
        return c.ts_node_child_count(node.raw);
    }

    /// Remember to check with isNull
    pub fn getNamedChild(node: Node, child_index: u32) Node {
        return .{ .raw = c.ts_node_named_child(node.raw, child_index) };
    }

    pub fn namedChildIterator(node: Node) NamedChildIterator {
        return NamedChildIterator{ .node = node };
    }

    pub fn getNamedChildCount(node: Node) u32 {
        return c.ts_node_named_child_count(node.raw);
    }

    /// Remember to check with isNull
    pub fn getChildByFieldName(node: Node, field_name: []const u8) Node {
        return c.ts_node_child_by_field_name(node.raw, field_name.ptr, @intCast(u32, field_name.len));
    }

    /// Remember to check with isNull
    pub fn getChildByFieldId(node: Node, field_id: FieldId) Node {
        return c.ts_node_child_by_field_name(node.raw, field_id);
    }

    // TODO: Sibling iterators

    pub fn getNextSibling(node: Node) Node {
        return .{ .raw = c.ts_node_next_sibling(node.raw) };
    }

    pub fn getPrevSibling(node: Node) Node {
        return .{ .raw = c.ts_node_prev_sibling(node.raw) };
    }

    pub fn getNextNamedSibling(node: Node) Node {
        return .{ .raw = c.ts_node_next_named_sibling(node.raw) };
    }

    pub fn getPrevNamedSibling(node: Node) Node {
        return .{ .raw = c.ts_node_prev_named_sibling(node.raw) };
    }

    // TODO: Niche and I'm lazy
    // pub extern fn ts_node_first_child_for_byte(Node, u32) Node;
    // pub extern fn ts_node_first_named_child_for_byte(Node, u32) Node;
    // pub extern fn ts_node_descendant_for_byte_range(Node, u32, u32) Node;
    // pub extern fn ts_node_descendant_for_point_range(Node, Point, Point) Node;
    // pub extern fn ts_node_named_descendant_for_byte_range(Node, u32, u32) Node;
    // pub extern fn ts_node_named_descendant_for_point_range(Node, Point, Point) Node;

    /// Apply a text diff to the node
    pub fn edit(node: Node, the_edit: *const InputEdit) void {
        c.ts_node_edit(node.raw, the_edit);
    }

    pub fn eql(a: Node, b: Node) bool {
        return c.ts_node_eq(a.raw, b.raw);
    }
};
