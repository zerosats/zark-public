use bitcoin_relations::part;
fn main(
    packed:pub [Field;29], statement:[u8;877],current:[u8;388],current_vk:[Field;115],current_proof:[Field;458],
    previous_authorization:[u8;877],previous_partial:[u8;32],
    capability:[u8;32],current_recovery:[u8;32],current_issuance:[u8;32],server_salt:[u8;32],
    user:[u8;32],alpha:[u8;32],beta:[u8;32],
    funding_salt:[u8;32],exit_salt:[u8;32],nonce_salt:[u8;32],
    txid:[u8;32],vout:u32,amount:u64,fee:u64,destination:[u8;64],session_auth_point:[u8;64],
    deposit_txid:[u8;32],deposit_vout:u32,deposit_amount:u64,
) {
    packing::bind::<877,29>(statement,packed);
    let cfg=part::<877,224>(statement,653);
    lineage::verify_transfer_predecessor(current,previous_authorization,current_vk,current_proof,previous_partial,server_salt,cfg);
    transfer::exit::exit(statement,current,capability,current_recovery,current_issuance,server_salt,user,alpha,beta,funding_salt,exit_salt,nonce_salt,txid,vout,amount,fee,destination,session_auth_point,deposit_txid,deposit_vout,deposit_amount);
}
