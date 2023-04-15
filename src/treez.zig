pub const c = @import("c.zig");
pub const std = @import("std");

pub const Logger = c.Logger;
pub const Range = c.Range;
pub const Input = c.Input;
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

pub const Tree = struct {
    handle: *c.Tree,
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
