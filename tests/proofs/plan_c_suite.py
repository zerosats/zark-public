"""Canonical v9 proof-suite order, packages, public byte counts and graph."""
ROLES = [
    ('deposit_authorization','private-deposit-authorize',1466,0),
    ('sender_from_origin','private-sender-from-origin',685,1),
    ('sender_from_transfer','private-sender-from-transfer',685,1),
    ('receiver_authorization','private-receiver-authorize',877,1),
    ('exit_from_origin','private-exit-from-origin',877,1),
    ('exit_from_transfer','private-exit-from-transfer',877,1),
]
LIBRARIES=['relations','recursion','private-recovery-relations','private-lineage-relations','private-transfer-relations','private-deposit-relations','app-hash','fixed-generator','packing','vendor']
