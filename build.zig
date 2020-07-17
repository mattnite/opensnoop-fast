const std = @import("std");
const Builder = @import("std").build.Builder;
const packages = @import("zig-cache/packages.zig").list;
const builtin = @import("builtin");

pub fn build(b: *Builder) !void {
    const obj = b.addObject("probe", "src/probe.zig");
    obj.setBuildMode(.ReleaseFast);
    obj.setOutputDir("src");
    obj.setTarget(std.zig.CrossTarget{
        .cpu_arch = if (builtin.endian == .Big) .bpfeb else .bpfel,
        .os_tag = .freestanding,
    });
    const bpf = for (packages) |pkg| {
        if (std.mem.eql(u8, pkg.name, "bpf")) {
            break pkg;
        }
    } else return error.NoBpfPackage;
    obj.addPackage(bpf);
    obj.addIncludeDir("/usr/include");

    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("opensnoop-fast", "src/main.zig");
    for (packages) |pkg| {
        exe.addPackage(pkg);
    }

    exe.addIncludeDir("/usr/include");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();
    exe.step.dependOn(&obj.step);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
