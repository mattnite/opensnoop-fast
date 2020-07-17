// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Matt Knight
//
// Based on opensnoop(8) from BCC by Brendan Gregg and others.
// 14-Feb-2020   Brendan Gregg   Created this.
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix

const std = @import("std");
const c = @cImport({
    @cInclude("linux/limits.h");
});

const TASK_COMM_LEN = 16; // not available from linux uapi
const NAME_MAX = c.NAME_MAX;

pub const Args = struct {
    fname: *const [*:0]u8,
    flags: usize,
};

pub const Event = struct {
    ts: u64,
    pid: u32,
    uid: u32,
    ret: isize,
    flags: usize,
    comm: [TASK_COMM_LEN]u8,
    fname: [NAME_MAX]u8,
};

pub const PidTidTag = enum {
    Pid,
    Tid,
};

pub const PidTidFilter = union(PidTidTag) {
    Pid: u32,
    Tid: u32,
};

pub const Config = struct {
    pid_tid: ?PidTidFilter = null,
    uid: ?u32 = null,
    flags: u32 = 0,
    failed: bool = false,

    const Self = @This();

    pub fn filter(self: *const Self, pid: u32, tid: u32, uid: u32) !void {
        if (self.pid_tid) |tag| {
            switch (tag) {
                .Pid => |p| if (p != pid) return error.Filter,
                .Tid => |t| if (t != tid) return error.Filter,
            }
        }

        if (self.uid) |u| {
            if (u != uid) return error.Filter;
        }
    }
};
