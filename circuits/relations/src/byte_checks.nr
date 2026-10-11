// u8 inputs are range-constrained; their sum is at most 8160, below
// the native field modulus. Zero sum is equivalent to all 32 bytes being zero.
pub fn is_nonzero(bytes:[u8;32]) -> bool {
    let mut sum:Field = 0;
    for byte in bytes { sum += byte as Field; }
    sum != 0
}

#[test]
fn byte_nonzero_boundaries() {
    assert(!is_nonzero([0;32]));
    assert(is_nonzero([255;32]));
    for i in 0..32 {
        for bit in 0..8 {
            let mut bytes=[0;32];bytes[i]=(1 as u8) << (bit as u8);
            assert(is_nonzero(bytes));
        }
        let mut bytes=[0;32];bytes[i]=255;assert(is_nonzero(bytes));
    }
}

fn context() -> [u8;237] {
    let mut bytes=[0;237];bytes[0]=10;
    for i in 0..6 { bytes[4+32*i]=1; }
    bytes
}
fn intent() -> [u8;205] {
    let mut bytes=[0;205];bytes[0]=10;
    for i in 0..5 { bytes[4+32*i]=1; }
    bytes[164]=1;
    bytes
}
#[test]
fn accepts_single_and_batch_contexts() {
    let mut value=context();super::context10(value);
    value[204]=1;
    for i in 0..32 {
        let mut batched=value;batched[205+i]=255;super::context10(batched);
    }
    let mut value=intent();super::handover_intent10(value);
    value[172]=1;
    for i in 0..32 {
        let mut batched=value;batched[173+i]=255;super::handover_intent10(batched);
    }
}
fn reject_context_field(index:u32) {
    let mut value=context();value[4+32*index]=0;super::context10(value);
}
#[test(should_fail_with = "empty context field")]
fn rejects_empty_deployment() { reject_context_field(0); }
#[test(should_fail_with = "empty context field")]
fn rejects_empty_coin() { reject_context_field(1); }
#[test(should_fail_with = "empty context field")]
fn rejects_empty_predecessor() { reject_context_field(2); }
#[test(should_fail_with = "empty context field")]
fn rejects_empty_session() { reject_context_field(3); }
#[test(should_fail_with = "empty context field")]
fn rejects_empty_intent() { reject_context_field(4); }
#[test(should_fail_with = "empty context field")]
fn rejects_empty_session_key() { reject_context_field(5); }
#[test(should_fail_with = "context batch scope")]
fn rejects_empty_batch_context() { let mut value=context();value[204]=1;super::context10(value); }
#[test(should_fail_with = "context batch scope")]
fn rejects_batch_in_single_context() { let mut value=context();value[205]=1;super::context10(value); }
#[test(should_fail_with = "context scope")]
fn rejects_unknown_context_scope() { let mut value=context();value[204]=2;super::context10(value); }
#[test(should_fail_with = "handover batch scope")]
fn rejects_empty_batch_intent() { let mut value=intent();value[172]=1;super::handover_intent10(value); }
#[test(should_fail_with = "handover batch scope")]
fn rejects_batch_in_single_intent() { let mut value=intent();value[173]=1;super::handover_intent10(value); }
#[test(should_fail_with = "handover scope")]
fn rejects_unknown_intent_scope() { let mut value=intent();value[172]=2;super::handover_intent10(value); }
#[test(should_fail_with = "handover starting revision")]
fn rejects_zero_revision() { let mut value=intent();value[164]=0;super::handover_intent10(value); }
