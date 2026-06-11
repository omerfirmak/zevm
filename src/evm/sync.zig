const std = @import("std");

pub fn SpinLockOnce(comptime f: fn () void) type {
    const NotInitialized: usize = 0;
    const InProgress: usize = 1;
    const Done: usize = 2;

    return struct {
        cur_state: std.atomic.Value(usize) = .init(NotInitialized),

        pub fn call(self: *@This()) void {
            if (self.cur_state.load(.acquire) == Done) return;
            if (self.cur_state.cmpxchgStrong(NotInitialized, InProgress, .acq_rel, .acquire) == null) {
                f();
                self.cur_state.store(Done, .release);
                return;
            }
            while (self.cur_state.load(.acquire) != Done) std.atomic.spinLoopHint();
        }
    };
}
