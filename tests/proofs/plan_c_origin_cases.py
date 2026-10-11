"""Rebind outer origin state while violating its exact prior proof statement."""
import copy

from plan_c_fixtures import Fixtures, h


def check_origin_bindings(run, fixtures, origin, deposit):
    # Local authorization validation is reused from the pinned deposit role.
    # Recompute every outer commitment and signature so the exact recursive
    # public-byte binding must reject this altered signing digest.
    changed = copy.deepcopy(origin)
    digest = changed['binding_digest']
    changed['binding_digest'] = bytes([digest[0] ^ 1]) + digest[1:]
    changed['issuance_digest'] = h('ZARK/private-handoff/issuance/v1',
                                  changed['binding_digest'], changed['partial'])
    changed['state'] = h('ZARK/private-handoff/state/v1', fixtures.domain,
                         fixtures.funding, changed['cap_commit'],
                         changed['recovery_commit'], changed['server_commit'],
                         fixtures.policy, changed['issuance_digest'])
    sender, _, _ = fixtures.handover(changed, 1)
    sender.update(fixtures.origin_predecessor(changed, 'previous'))
    sender.update(run.recursive(deposit, 'previous'))
    run.negative('sender_from_origin', 'rebound-origin-signing-digest', sender)
    exit_values = fixtures.exit(changed, 0)
    exit_values.update(fixtures.origin_predecessor(changed, 'current'))
    exit_values.update(run.recursive(deposit, 'current'))
    run.negative('exit_from_origin', 'rebound-exit-origin-signing-digest', exit_values)

    # Preserve a canonical, distinct role set and the allowed deposit hash.
    # Changing other role assignments must still invalidate its prior proof.
    config = bytearray(fixtures.config)
    config[64:96], config[128:160] = config[128:160], config[64:96]
    other = Fixtures(bytes(config), deployment=fixtures.domain[4:36])
    sender, _, _ = other.handover(origin, 1)
    sender.update(other.origin_predecessor(origin, 'previous'))
    sender.update(run.recursive(deposit, 'previous'))
    run.negative('sender_from_origin', 'rebound-origin-configuration', sender)
