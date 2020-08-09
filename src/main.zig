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
const common = @import("common.zig");
const Data = common.Data;
const pid_t = std.os.pid_t;

fn print_usage(params: anytype) !void {
    const stderr = std.io.getStdErr().outStream();
    try stderr.print("Usage: opensnoop-fast ", .{});
    try clap.usage(stderr, &params);
    try stderr.print("\n", .{});
    try clap.help(stderr, &params);
}

var timestamp = false;
var print_uid = false;
var failed_only = false;
var extended_fields: ?[]const u8 = null;
var pid: ?pid_t = null;
var tid: ?u32 = null;
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
    const event = std.mem.bytesAsValue(*Event, data);

    // name filtering is currently done in user space
    const ret = if (e.ret >= 0) .{ .fd = e.ret, .err = 0 } else .{ .fd = -1, .err = -e.ret };
    if (name) |n| {
        if (std.mem.indexOf(u8, event.comm, n) == null) return null;
    }

    if (timestamp)
        stdout.print(timestamp_fmt, .{ts}) catch {};

    if (print_uid)
        stdout.print(uid_fmt, .{e.comm}) catch {};

    stdout.print(regular_fmt, .{ e.pid, e.comm, ret.fd, ret.err }) catch {};

    if (exended)
        stdout.print(extended_fmt, .{e.flags}) catch {};

    stdout.print("{}\n", .{e.fname}) catch {};
}

fn handle_lost_event(ctx: usize, cpu: i32, cnt: u64) void {
    stderr.print("Lost {} events on CPU #{}!\n", .{ cnt, cpu }) catch {};
}

pub fn main() anyerror!void {
    @setEvalBranchQuota(4000);
    const obj = bpf.ComptimeObject.init("probe.o");
    const events = obj.get_map(bpf.PerfEventArray, "events");
    defer events.deinit();

    const params = comptime [_]clap.Param(clap.Help){
        try clap.parseParam("-h, --help                     this usage message"),
        try clap.parseParam("-d, --duration <seconds>       trace duration and use buffers"),
        try clap.parseParam("-e, --extended-fields <field>  show extended fields"),
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

    // get regular flags
    timestamp = args.flag("-T");
    print_uid = args.flag("-U");
    failed_only = args.flag("-x");
    extended_fields = args.option("-e");

    // process arguments

    if (pid != null and tid != null) {
        return error.OnlyPidOrTid;
    }

    obj.set_rodata("config", Config{
        .pid_tid = if (pid) |p|
            .{ .pid = p }
        else if (tid) |t|
            .{ .tid = t }
        else
            null,
        .uid = uid,
        .flags = 0,
        .failed = failed_only,
    });

    // attach kprobe "do_sys_open" trace_entry
    // attach kretprobe "do_sys_open" trace_return

    // print header
    const stdout = std.io.getStdOut().outStream();
    if (timestamp) {
        try stdout.print(timestamp_fmt, .{"TIME"});
    }

    if (print_uid) {
        try stdout.print(uid_fmt, .{"UID"});
    }

    try stdout.print(regular_fmt, .{ "PID", "COMM", "FD", "ERR" });
    if (extended_fields != null) {
        try stdout.print("{: <8}", .{"FLAGS"});
    }

    try stdout.print("\n", .{});

    var perf_buffer = try perf.Buffer.init(
        allocator,
        events.fd,
        perf_buffer_pages,
        handle_event,
        handle_lost_event,
        ctx,
    );
    defer perf_buffer.deinit();

    // while less than duration
    //      poll event buffer, call print_event
    //      get event

    //      split return  and errno
    //      filter return value
    //      filter comm name

    //      if timestamp then print timestamp
    //      if print uid then print uid
    //      print tid or pid, command, return,
    //      if extended_fields print it
    //      print fname
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
