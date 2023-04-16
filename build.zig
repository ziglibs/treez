const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("treez", .{
        .source_file = .{ .path = "treez.zig" },
    });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Example

    const exe = b.addExecutable(.{
        .name = "treez-example",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "example.zig" },
        .target = target,
        .optimize = optimize,
    });

    exe.linkLibC();

    exe.addCSourceFile("vendor/tree-sitter/lib/src/lib.c", &.{});
    exe.addIncludePath("vendor/tree-sitter/lib/include");
    exe.addIncludePath("vendor/tree-sitter/lib/src");

    exe.addCSourceFile("vendor/tree-sitter-zig/src/parser.c", &.{});
    exe.addIncludePath("vendor/tree-sitter-zig/src");

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("example", "Run the example");
    run_step.dependOn(&run_cmd.step);

    // Tests

    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "treez.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
