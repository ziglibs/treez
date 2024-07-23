const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("treez", .{
        .root_source_file = b.path("treez.zig"),
    });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    b.installArtifact(b.dependency("tree-sitter", .{
        .target = target,
        .optimize = optimize,
    }).artifact("tree-sitter"));

    // Example

    // const exe = b.addExecutable(.{
    //     .name = "treez-example",
    //     // In this case the main source file is merely a path, however, in more
    //     // complicated build scripts, this could be a generated file.
    //     .root_source_file = b.path("example/example.zig"),
    //     .target = target,
    //     .optimize = optimize,
    // });

    // Added module import for example to use directly, requires changing _ = to const treez = at the top
    // exe.root_module.addImport("treez", treez);

    // exe.linkLibC();

    // exe.linkLibrary(b.dependency("tree-sitter", .{
    //     .target = target,
    //     .optimize = optimize,
    // }).artifact("tree-sitter"));

    // exe.linkLibrary(b.dependency("tree-sitter-zig", .{
    //     .target = target,
    //     .optimize = optimize,
    // }).artifact("tree-sitter-zig"));

    // b.installArtifact(exe);

    // const run_cmd = b.addRunArtifact(exe);
    // run_cmd.step.dependOn(b.getInstallStep());

    // if (b.args) |args| {
    //     run_cmd.addArgs(args);
    // }

    // const run_step = b.step("example", "Run the example");
    // run_step.dependOn(&run_cmd.step);
}
