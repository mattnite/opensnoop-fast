// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Matt Knight
//
// Base on the opensnoop probe as part of libbpf-tools
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

usingnamespace @import("common.zig");
const std = @import("std");
const bpf = @import("bpf").kern;
const c = @cImport({
    @cInclude("linux/version.h");
});

const Map = bpf.Map;
const PerfEventArray = bpf.PerfEventArray;

export var config: Config = undefined;

export const start linksection(".maps") = Map(u32, Args, .hash, 10240).init();
export const events linksection(".maps") = PerfEventArray.init();

// static variables linked at loadtime
const SyscallEnterArgs = struct {
    unused: u64,
    syscall_nr: usize,
    filename: usize,
    flags: usize,
    mode: usize,
};

const SyscallExitArgs = struct {
    unused: u64,
    syscall_nr: usize,
    ret: isize,
};

inline fn trace_enter(ctx: *SyscallEnterArgs) !void {
    const id = bpf.get_current_pid_tgid();
    const tgid = @truncate(u32, id >> 32);
    const pid = @truncate(u32, id);

    try config.filter(pid, tgid, @truncate(u32, bpf.get_current_uid_gid()));

    const args = Args{
        .fname = @intToPtr(*const [*:0]u8, ctx.filename),
        .flags = ctx.flags,
    };

    try start.update(.any, &pid, &args);
}

inline fn trace_exit(ctx: *SyscallExitArgs) !void {
    const id = bpf.get_current_pid_tgid();
    const pid = @truncate(u32, id >> 32);
    defer start.delete(&pid) catch {};

    if (config.failed and ctx.ret >= 0) {
        return;
    }

    const args = start.lookup(&pid) orelse return error.NotFound;
    var event = Event{
        .ts = bpf.ktime_get_ns(),
        .pid = pid,
        .uid = @truncate(u32, id),
        .flags = args.flags,
        .ret = ctx.ret,
        .comm = undefined,
        .fname = undefined,
    };

    try bpf.get_current_comm(&event.comm);
    try bpf.probe_read_user_str(&event.fname, args.fname);
    try bpf.perf_event_output(ctx, &events.def, .current_cpu, std.mem.asBytes(&event));
}

export fn enter_open(ctx: *SyscallEnterArgs) linksection("tracepoint/syscalls/sys_enter_open") c_int {
    trace_enter(ctx) catch {};
    return 0;
}

export fn enter_openat(ctx: *SyscallEnterArgs) linksection("tracepoint/syscalls/sys_enter_openat") c_int {
    trace_enter(ctx) catch {};
    return 0;
}

export fn exit_open(ctx: *SyscallExitArgs) linksection("tracepoint/syscalls/sys_exit_open") c_int {
    trace_exit(ctx) catch {};
    return 0;
}

export fn exit_openat(ctx: *SyscallExitArgs) linksection("tracepoint/syscalls/sys_exit_openat") c_int {
    trace_exit(ctx) catch {};
    return 0;
}

export const _license linksection(".license") = "GPL";
export const _version linksection(".version") = c.LINUX_VERSION_CODE;
