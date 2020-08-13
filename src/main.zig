// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Matt Knight
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

const std = @import("std");
const clap = @import("clap");
const bpf = @import("bpf").user;
const perf = bpf.perf;
usingnamespace @import("common.zig");
const pid_t = std.os.pid_t;
const fd_t = std.os.fd_t;

fn print_usage(params: anytype) !void {
    try stderr.print("Usage: opensnoop-fast ", .{});
    try clap.usage(stderr, &params);
    try stderr.print("\n", .{});
    try clap.help(stderr, &params);
}

var timestamp = false;
var print_uid = false;
var failed_only = false;
var extended = false;
var pid: ?pid_t = null;
var tid: ?i32 = null;
var uid: ?u32 = null;
var name: ?[]const u8 = null;
var duration: ?[]usize = null;

const timestamp_fmt = "{: <8} ";
const uid_fmt = "{: <6} ";
const regular_fmt = "{: <6} {: <16} {: <3} {: <3}";
const extended_fmt = "{X:0>8}";

const perf_buffer_pages = 64;
const perf_buffer_time_ms = 10;
const perf_poll_timeout_ms = 100;

const stdout = std.io.getStdOut().outStream();
const stderr = std.io.getStdErr().outStream();

fn handle_event(ctx: usize, cpu: i32, data: []u8) void {
    if (data.len != @sizeOf(Event)) {
        stderr.print(
            "data size ({}) does not match size of Event ({})\n",
            .{ data.len, @sizeOf(Event) },
        ) catch {};
    }

    var e: Event = undefined;
    std.mem.copy(u8, std.mem.asBytes(&e), data);

    // name filtering is currently done in user space
    const Ret = struct { fd: isize, err: isize };
    const ret: Ret = if (e.ret >= 0) .{ .fd = e.ret, .err = 0 } else .{ .fd = -1, .err = -e.ret };
    if (name) |n| {
        if (std.mem.indexOf(u8, &e.comm, n) == null) return;
    }

    if (timestamp) {
        var ts: std.os.timespec = undefined;
        std.os.clock_gettime(std.os.CLOCK_REALTIME, &ts) catch return;

        stdout.print(timestamp_fmt, .{ts}) catch {};
    }

    if (print_uid)
        stdout.print(uid_fmt, .{e.comm}) catch {};

    stdout.print(regular_fmt, .{ e.pid, e.comm, ret.fd, ret.err }) catch {};

    if (extended)
        stdout.print(extended_fmt, .{e.flags}) catch {};

    stdout.print("{}\n", .{e.fname}) catch {};
}

fn handle_lost_event(ctx: usize, cpu: i32, cnt: u64) void {
    stderr.print("Lost {} events on CPU #{}!\n", .{ cnt, cpu }) catch {};
}

pub fn main() anyerror!void {
    @setEvalBranchQuota(4000);
    var obj = bpf.ComptimeObject.init("probe.o");
    const events = obj.get_map(bpf.PerfEventArray, "events");

    const params = comptime [_]clap.Param(clap.Help){
        try clap.parseParam("-h, --help                     this usage message"),
        try clap.parseParam("-d, --duration <seconds>       trace duration and use buffers"),
        try clap.parseParam("-e, --extended                 show extended fields"),
        try clap.parseParam("-n, --name <name>              process name to match on I/O issue"),
        try clap.parseParam("-p, --pid <pid>                trace specific process ID"),
        try clap.parseParam("-t, --tid <tid>                trace specific thread ID"),
        try clap.parseParam("-u, --uid <uid>                trace this user ID only"),
        try clap.parseParam("-T, --timestamp                include timestamp in output"),
        try clap.parseParam("-U, --print-uid                print UID column"),
        try clap.parseParam("-x, --failed                   only show failed opens"),
    };

    var args = clap.parse(clap.Help, &params, std.heap.page_allocator) catch |err| {
        if (err == error.InvalidArgument) {
            try print_usage(params);
            std.os.exit(1);
        } else {
            return err;
        }
    };
    defer args.deinit();

    if (args.flag("-h")) {
        try print_usage(params);
        std.os.exit(1);
    }

    if (pid != null and tid != null) {
        try print_usage(params);
        return error.OnlyPidOrTid;
    }

    // get regular flags
    timestamp = args.flag("-T");
    print_uid = args.flag("-U");
    failed_only = args.flag("-x");
    extended = args.flag("-e");

    // process arguments
    // - duration
    // - name
    // - pid
    // - tid
    // - uid

    obj.set_rodata("config", Config{
        .pid_tid = if (pid) |p|
            PidTidFilter{ .pid = p }
        else if (tid) |t|
            PidTidFilter{ .tid = t }
        else
            null,
        .uid = uid,
        .flags = 0,
        .failed = failed_only,
    });

    // attach kprobe "do_sys_open" trace_entry
    // attach kretprobe "do_sys_open" trace_return

    // print header
    if (timestamp) {
        try stdout.print(timestamp_fmt, .{"TIME"});
    }

    if (print_uid) {
        try stdout.print(uid_fmt, .{"UID"});
    }

    try stdout.print(regular_fmt, .{ "PID", "COMM", "FD", "ERR" });
    if (extended) {
        try stdout.print("{: <8}", .{"FLAGS"});
    }

    try stdout.print("\n", .{});

    var perf_buffer = try perf.Buffer.init(
        std.heap.page_allocator,
        events.fd,
        perf_buffer_pages,
        null,
        handle_event,
        handle_lost_event,
        0,
    );
    defer perf_buffer.deinit();

    // while less than duration
    //      poll event buffer
}

test "probe programs can be loaded" {
    const obj = bpf.ComptimeObject.init("probe.o");

    const program_names = .{
        "tracepoint/syscalls/sys_enter_open",
        "tracepoint/syscalls/sys_enter_openat",
        "tracepoint/syscalls/sys_exit_open",
        "tracepoint/syscalls/sys_exit_openat",
    };

    for (program_names) |prog_name| {
        const prog = obj.get_prog(prog_name);
        try prog.load();
        defer prog.unload();
    }
}
