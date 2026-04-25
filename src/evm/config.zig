pub const Config = struct {
    fork: @import("spec.zig").Spec,
    tracing_enabled: bool = false,
};
