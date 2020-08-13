const zkg = @import("zkg");

pub const clap = zkg.import.git(
    "https://github.com/mattnite/zig-clap.git",
    "anytype",
    "clap.zig",
);

pub const bpf = zkg.import.git(
    "https://github.com/mattnite/bpf.git",
    "master",
    null,
);
