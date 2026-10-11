# Protocol and trust

A coin is a Bitcoin output controlled jointly by its owner and a cosigner.
Neither party can spend it alone through the cooperative path. The owner keeps
its secret share and generates proofs locally; the cosigner maintains the other
share and validates each authorized state transition.

## Deposit

The wallet establishes an origin with the signer and obtains the spending and
recovery material. Funding puts Bitcoin into the jointly controlled output.
The sponsored-deposit faucet pays that funding transaction for the user. The
wallet saves the recovery data before broadcasting the funding transaction.
The faucet supplies test coins; it does not replace the deposit protocol.

## Transfer

The receiver creates an invitation. Sender and receiver prove the required
relations as their shares are replaced while the Bitcoin spending key remains
the same. The signer commits the authorized transition before returning its
response. Exact retries recover the same result after interruption.

A successful off-chain transfer does not require another Bitcoin transaction.
Funding still needs confirmation. The current policy permits eight owners in
total, including the depositor; the final owner can withdraw but cannot transfer
again. A swap consumes an ownership transition on each participating coin.

## Withdrawal and recovery

Owners can cooperate with the signer to withdraw. They also retain signed
Bitcoin recovery transactions for a unilateral exit after the applicable delay.
Recovery transactions are private wallet material and must be backed up.
An application reinstall, source update or new deployment must not overwrite an
old wallet's pending operations or recovery files.

The MutinyNet demo schedule is 34,560 blocks initially, decreasing by 2,880
blocks per ownership transition, with a 1,440-block margin. The last owner's
schedule is therefore 14,400 blocks. These are block counts; wall-clock time
depends on the network. Recovery rehearsals use isolated regtest so tests can
mine the required blocks immediately.

## Trust boundaries

The cosigner must delete obsolete secret shares and avoid colluding with former
owners. Zero-knowledge proofs enforce the implemented relations; they do not
prove secure deletion. Owners must preserve recovery material and monitor the
chain. The signer database and independent checkpoint together detect certain
rollback or incomplete-commit conditions; the checkpoint is not a backup.

Only one active signer instance may use a deployment's signing identity and
state. Clients pin its identity, TLS certificate, circuit suite and service
settings. Replacing that identity creates a new deployment and new profiles.

The wallet is an unaudited research prototype. Proofs do not hide Bitcoin funding
or exit transactions, or automatically eliminate timing and network metadata.
