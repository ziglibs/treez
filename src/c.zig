// TREE_SITTER_LANGUAGE_VERSION 14
// TREE_SITTER_MIN_COMPATIBLE_LANGUAGE_VERSION 13

// Types

pub const Symbol = enum(u16) { _ };
pub const FieldId = enum(u16) { _ };

pub const InputEncoding = enum(c_uint) {
    utf_8,
    utf_16,
};

pub const SymbolType = enum(c_uint) {
    regular,
    anonymous,
    auxiliary,
};

pub const Point = extern struct {
    row: u32,
    column: u32,
};
pub const Range = extern struct {
    start_point: Point,
    end_point: Point,
    start_byte: u32,
    end_byte: u32,
};
pub const Input = extern struct {
    payload: ?*anyopaque,
    read: ?*const fn (payload: ?*anyopaque, byte_index: u32, position: Point, bytes_read: *u32) callconv(.C) [*:0]const u8,
    encoding: InputEncoding,
};

pub const LogType = enum(c_uint) {
    parse,
    lex,
};

pub const Logger = extern struct {
    payload: ?*anyopaque,
    log: ?*const fn (payload: ?*anyopaque, log_type: LogType, log: [*:0]const u8) callconv(.C) void,
};
pub const InputEdit = extern struct {
    start_byte: u32,
    old_end_byte: u32,
    new_end_byte: u32,
    start_point: Point,
    old_end_point: Point,
    new_end_point: Point,
};
pub const Node = extern struct {
    context: [4]u32,
    id: ?*const anyopaque,
    tree: ?*const Tree,
};

pub const TreeCursor = extern struct {
    tree: ?*const anyopaque,
    id: ?*const anyopaque,
    context: [2]u32,
};

pub const QueryCapture = extern struct {
    node: Node,
    index: u32,
};

pub const Quantifier = enum(c_uint) {
    zero,
    zero_or_one,
    zero_or_more,
    one,
    one_or_more,
};

pub const QueryMatch = extern struct {
    id: u32,
    pattern_index: u16,
    capture_count: u16,
    captures: [*]const QueryCapture,
};

pub const QueryPredicateStepType = enum(c_uint) {
    done,
    capture,
    string,
};

pub const QueryPredicateStep = extern struct {
    type: QueryPredicateStepType,
    value_id: u32,
};

pub const QueryError = enum(c_uint) {
    none,
    syntax,
    node_type,
    field,
    capture,
    structure,
    language,
};

// Parser

pub const Parser = opaque {};
pub const Language = opaque {};
pub const Tree = opaque {};
pub const Query = opaque {};
pub const QueryCursor = opaque {};

pub extern fn ts_parser_new() ?*Parser;
pub extern fn ts_parser_delete(parser: ?*Parser) void;
pub extern fn ts_parser_set_language(self: ?*Parser, language: ?*const Language) bool;
pub extern fn ts_parser_language(self: ?*const Parser) ?*const Language;
pub extern fn ts_parser_set_included_ranges(self: ?*Parser, ranges: [*]const Range, length: u32) bool;
pub extern fn ts_parser_included_ranges(self: ?*const Parser, length: *u32) [*]const Range;
pub extern fn ts_parser_parse(self: ?*Parser, old_tree: ?*const Tree, input: Input) ?*Tree;
pub extern fn ts_parser_parse_string(self: ?*Parser, old_tree: ?*const Tree, string: [*]const u8, length: u32) ?*Tree;
pub extern fn ts_parser_parse_string_encoding(self: ?*Parser, old_tree: ?*const Tree, string: [*]const u8, length: u32, encoding: InputEncoding) ?*Tree;
pub extern fn ts_parser_reset(self: ?*Parser) void;
pub extern fn ts_parser_set_timeout_micros(self: ?*Parser, timeout: u64) void;
pub extern fn ts_parser_timeout_micros(self: ?*const Parser) u64;
pub extern fn ts_parser_set_cancellation_flag(self: ?*Parser, flag: ?*const usize) void;
pub extern fn ts_parser_cancellation_flag(self: ?*const Parser) ?*const usize;
pub extern fn ts_parser_set_logger(self: ?*Parser, logger: Logger) void;
pub extern fn ts_parser_logger(self: ?*const Parser) Logger;
pub extern fn ts_parser_print_dot_graphs(self: ?*Parser, file: c_int) void;

pub extern fn ts_tree_copy(self: ?*const Tree) ?*Tree;
pub extern fn ts_tree_delete(self: ?*Tree) void;
pub extern fn ts_tree_root_node(self: ?*const Tree) Node;
pub extern fn ts_tree_root_node_with_offset(self: ?*const Tree, offset_bytes: u32, offset_point: Point) Node;
pub extern fn ts_tree_language(?*const Tree) ?*const Language;
pub extern fn ts_tree_included_ranges(?*const Tree, length: *u32) [*]Range;
pub extern fn ts_tree_edit(self: ?*Tree, edit: *const InputEdit) void;
pub extern fn ts_tree_get_changed_ranges(old_tree: ?*const Tree, new_tree: ?*const Tree, length: *u32) [*]Range;
pub extern fn ts_tree_print_dot_graph(?*const Tree, file_descriptor: c_int) void;

pub extern fn ts_node_type(Node) [*c]const u8;
pub extern fn ts_node_symbol(Node) Symbol;
pub extern fn ts_node_start_byte(Node) u32;
pub extern fn ts_node_start_point(Node) Point;
pub extern fn ts_node_end_byte(Node) u32;
pub extern fn ts_node_end_point(Node) Point;
pub extern fn ts_node_string(Node) [*c]u8;
pub extern fn ts_node_is_null(Node) bool;
pub extern fn ts_node_is_named(Node) bool;
pub extern fn ts_node_is_missing(Node) bool;
pub extern fn ts_node_is_extra(Node) bool;
pub extern fn ts_node_has_changes(Node) bool;
pub extern fn ts_node_has_error(Node) bool;
pub extern fn ts_node_parent(Node) Node;
pub extern fn ts_node_child(Node, u32) Node;
pub extern fn ts_node_field_name_for_child(Node, u32) [*c]const u8;
pub extern fn ts_node_child_count(Node) u32;
pub extern fn ts_node_named_child(Node, u32) Node;
pub extern fn ts_node_named_child_count(Node) u32;
pub extern fn ts_node_child_by_field_name(self: Node, field_name: [*c]const u8, field_name_length: u32) Node;
pub extern fn ts_node_child_by_field_id(Node, FieldId) Node;
pub extern fn ts_node_next_sibling(Node) Node;
pub extern fn ts_node_prev_sibling(Node) Node;
pub extern fn ts_node_next_named_sibling(Node) Node;
pub extern fn ts_node_prev_named_sibling(Node) Node;
pub extern fn ts_node_first_child_for_byte(Node, u32) Node;
pub extern fn ts_node_first_named_child_for_byte(Node, u32) Node;
pub extern fn ts_node_descendant_for_byte_range(Node, u32, u32) Node;
pub extern fn ts_node_descendant_for_point_range(Node, Point, Point) Node;
pub extern fn ts_node_named_descendant_for_byte_range(Node, u32, u32) Node;
pub extern fn ts_node_named_descendant_for_point_range(Node, Point, Point) Node;
pub extern fn ts_node_edit([*c]Node, [*c]const InputEdit) void;
pub extern fn ts_node_eq(Node, Node) bool;

pub extern fn ts_tree_cursor_new(Node) TreeCursor;
pub extern fn ts_tree_cursor_delete([*c]TreeCursor) void;
pub extern fn ts_tree_cursor_reset([*c]TreeCursor, Node) void;
pub extern fn ts_tree_cursor_current_node([*c]const TreeCursor) Node;
pub extern fn ts_tree_cursor_current_field_name([*c]const TreeCursor) [*c]const u8;
pub extern fn ts_tree_cursor_current_field_id([*c]const TreeCursor) FieldId;
pub extern fn ts_tree_cursor_goto_parent([*c]TreeCursor) bool;
pub extern fn ts_tree_cursor_goto_next_sibling([*c]TreeCursor) bool;
pub extern fn ts_tree_cursor_goto_first_child([*c]TreeCursor) bool;
pub extern fn ts_tree_cursor_goto_first_child_for_byte([*c]TreeCursor, u32) i64;
pub extern fn ts_tree_cursor_goto_first_child_for_point([*c]TreeCursor, Point) i64;
pub extern fn ts_tree_cursor_copy([*c]const TreeCursor) TreeCursor;

pub extern fn ts_query_new(language: ?*const Language, source: [*c]const u8, source_len: u32, error_offset: [*c]u32, error_type: [*c]QueryError) ?*Query;
pub extern fn ts_query_delete(?*Query) void;
pub extern fn ts_query_pattern_count(?*const Query) u32;
pub extern fn ts_query_capture_count(?*const Query) u32;
pub extern fn ts_query_string_count(?*const Query) u32;
pub extern fn ts_query_start_byte_for_pattern(?*const Query, u32) u32;
pub extern fn ts_query_predicates_for_pattern(self: ?*const Query, pattern_index: u32, length: [*c]u32) [*c]const QueryPredicateStep;
pub extern fn ts_query_is_pattern_rooted(self: ?*const Query, pattern_index: u32) bool;
pub extern fn ts_query_is_pattern_non_local(self: ?*const Query, pattern_index: u32) bool;
pub extern fn ts_query_is_pattern_guaranteed_at_step(self: ?*const Query, byte_offset: u32) bool;
pub extern fn ts_query_capture_name_for_id(?*const Query, id: u32, length: [*c]u32) [*c]const u8;
pub extern fn ts_query_capture_quantifier_for_id(?*const Query, pattern_id: u32, capture_id: u32) Quantifier;
pub extern fn ts_query_string_value_for_id(?*const Query, id: u32, length: [*c]u32) [*c]const u8;
pub extern fn ts_query_disable_capture(?*Query, [*c]const u8, u32) void;
pub extern fn ts_query_disable_pattern(?*Query, u32) void;

pub extern fn ts_query_cursor_new() ?*QueryCursor;
pub extern fn ts_query_cursor_delete(?*QueryCursor) void;
pub extern fn ts_query_cursor_exec(?*QueryCursor, ?*const Query, Node) void;
pub extern fn ts_query_cursor_did_exceed_match_limit(?*const QueryCursor) bool;
pub extern fn ts_query_cursor_match_limit(?*const QueryCursor) u32;
pub extern fn ts_query_cursor_set_match_limit(?*QueryCursor, u32) void;
pub extern fn ts_query_cursor_set_byte_range(?*QueryCursor, u32, u32) void;
pub extern fn ts_query_cursor_set_point_range(?*QueryCursor, Point, Point) void;
pub extern fn ts_query_cursor_next_match(?*QueryCursor, match: [*c]QueryMatch) bool;
pub extern fn ts_query_cursor_remove_match(?*QueryCursor, id: u32) void;
pub extern fn ts_query_cursor_next_capture(?*QueryCursor, match: [*c]QueryMatch, capture_index: [*c]u32) bool;

pub extern fn ts_language_symbol_count(?*const Language) u32;
pub extern fn ts_language_symbol_name(?*const Language, Symbol) [*c]const u8;
pub extern fn ts_language_symbol_for_name(self: ?*const Language, string: [*c]const u8, length: u32, is_named: bool) Symbol;
pub extern fn ts_language_field_count(?*const Language) u32;
pub extern fn ts_language_field_name_for_id(?*const Language, FieldId) [*c]const u8;
pub extern fn ts_language_field_id_for_name(?*const Language, [*c]const u8, u32) FieldId;
pub extern fn ts_language_symbol_type(?*const Language, Symbol) SymbolType;
pub extern fn ts_language_version(?*const Language) u32;

pub extern fn ts_set_allocator(new_malloc: ?*const fn (usize) callconv(.C) ?*anyopaque, new_calloc: ?*const fn (usize, usize) callconv(.C) ?*anyopaque, new_realloc: ?*const fn (?*anyopaque, usize) callconv(.C) ?*anyopaque, new_free: ?*const fn (?*anyopaque) callconv(.C) void) void;
