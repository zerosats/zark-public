use super::{config,field,nonzero};
use super::schedule;

#[test]
fn all_seven_handoffs_have_exact_schedule_slots() {
    for i in 0..7 { schedule::predecessor(480,60,20,480-i*60); }
    schedule::validate(440,60,20);
}
#[test(should_fail_with = "final owner cannot transfer")]
fn eighth_owner_cannot_handoff() { schedule::predecessor(480,60,20,60); }
#[test(should_fail_with = "predecessor is off the fixed schedule")]
fn fractional_schedule_slot() { schedule::predecessor(480,60,20,419); }
#[test(should_fail_with = "recovery exceeds initial delay")]
fn delay_above_origin() { schedule::predecessor(480,60,20,540); }
#[test(should_fail_with = "eight-owner budget")]
fn insufficient_full_lifetime_budget() { schedule::validate(439,60,20); }
#[test(should_fail_with = "delay gap")]
fn zero_gap() { schedule::predecessor(480,0,20,480); }
#[test(should_fail_with = "recovery margin")]
fn invalid_margin() { schedule::validate(480,60,60); }
#[test(should_fail_with = "initial delay")]
fn initial_exceeds_bip68() { schedule::validate(65536,60,20); }
fn valid_config() -> [u8;224] {
    let mut value=[0;224];value[31]=42;
    for i in 0..6 { value[63+i*32]=(i+1) as u8; }
    value
}
#[test]
fn accepts_distinct_canonical_configuration() { config(valid_config()); }
#[test]
fn accepts_every_nonzero_byte_position() {
    for i in 0..32 { let mut value=[0;32];value[i]=1;nonzero(value); }
    nonzero([255;32]);
}
#[test(should_fail_with = "zero lineage value")]
fn rejects_zero_value() { nonzero([0;32]); }
#[test(should_fail_with = "zero lineage value")]
fn rejects_zero_origin_key() { let mut value=valid_config();value[31]=0;config(value); }
#[test(should_fail_with = "zero lineage value")]
fn rejects_zero_role_hash() { let mut value=valid_config();value[63]=0;config(value); }

#[test(should_fail_with = "noncanonical role hash")]
fn field_modulus() { let _=field([48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1]); }

#[test(should_fail_with = "noncanonical role hash")]
fn field_above_modulus() { let _=field([48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 2]); }

#[test(should_fail_with = "noncanonical role hash")]
fn field_maximum() { let _=field([255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]); }

#[test]
fn field_below_modulus() { let _=field([48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72, 121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 0]); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_0_1() { let mut value=valid_config();value[95]=1;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_0_2() { let mut value=valid_config();value[127]=1;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_0_3() { let mut value=valid_config();value[159]=1;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_0_4() { let mut value=valid_config();value[191]=1;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_0_5() { let mut value=valid_config();value[223]=1;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_1_2() { let mut value=valid_config();value[127]=2;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_1_3() { let mut value=valid_config();value[159]=2;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_1_4() { let mut value=valid_config();value[191]=2;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_1_5() { let mut value=valid_config();value[223]=2;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_2_3() { let mut value=valid_config();value[159]=3;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_2_4() { let mut value=valid_config();value[191]=3;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_2_5() { let mut value=valid_config();value[223]=3;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_3_4() { let mut value=valid_config();value[191]=4;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_3_5() { let mut value=valid_config();value[223]=4;config(value); }

#[test(should_fail_with = "duplicate role hash")]
fn duplicate_roles_4_5() { let mut value=valid_config();value[223]=5;config(value); }
