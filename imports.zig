const zkg = @import("zkg");

pub const clap = zkg.import.git(
    "https://github.com/Hejsil/zig-clap.git",
    "zig-master",
    "clap.zig",
);

pub const bpf = zkg.import.git(
    "https://github.com/mattnite/bpf.git",
    "master",
    null,
);
