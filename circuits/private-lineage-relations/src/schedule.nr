// Keep this policy bound aligned with protocol::handoff::INITIAL_OWNER_LIMIT.
// It is committed into the policy hash; changing it requires a fresh suite.
pub global OWNER_LIMIT: u32 = 8;

pub fn validate(initial:u32,gap:u32,margin:u32) {
    assert(initial > 0 & initial <= 65535, "initial delay");
    assert(gap > 0 & gap <= 65535, "delay gap");
    assert(margin > 0 & margin < gap, "recovery margin");
    assert(initial >= (OWNER_LIMIT-1)*gap+margin, "eight-owner budget");
}

// Only the first seven owners can authorize a successor. The eighth owner
// retains its exit/recovery path but cannot decrement the schedule again.
pub fn predecessor(initial:u32,gap:u32,margin:u32,delay:u32) {
    validate(initial,gap,margin);
    assert(delay <= initial, "recovery exceeds initial delay");
    let elapsed = initial-delay;
    assert(elapsed % gap == 0, "predecessor is off the fixed schedule");
    assert(elapsed / gap < OWNER_LIMIT-1, "final owner cannot transfer");
}
