use bitcoin_relations::part;
fn main(
    packed:pub [Field;29], statement:[u8;877],current:[u8;388],current_vk:[Field;115],current_proof:[Field;458],
    current_authorization:[u8;1466],current_partial:[u8;32],current_activation_partial:[u8;32],
    current_server_salt:[u8;32],current_origin_signature:[u8;64],
    current_origin_key_point:[u8;64],current_origin_nonce_point:[u8;64],
    capability:[u8;32],current_recovery:[u8;32],current_issuance:[u8;32],server_salt:[u8;32],
    user:[u8;32],alpha:[u8;32],beta:[u8;32],
    funding_salt:[u8;32],exit_salt:[u8;32],nonce_salt:[u8;32],
    txid:[u8;32],vout:u32,amount:u64,fee:u64,destination:[u8;64],session_auth_point:[u8;64],
    deposit_txid:[u8;32],deposit_vout:u32,deposit_amount:u64,
) {
    packing::bind::<877,29>(statement,packed);
    let cfg=part::<877,224>(statement,653);
    lineage::verify_origin_predecessor(current,current_authorization,current_vk,current_proof,current_partial,current_activation_partial,current_server_salt,current_origin_key_point,current_origin_nonce_point,current_origin_signature,cfg);
    transfer::exit::exit(statement,current,capability,current_recovery,current_issuance,server_salt,user,alpha,beta,funding_salt,exit_salt,nonce_salt,txid,vout,amount,fee,destination,session_auth_point,deposit_txid,deposit_vout,deposit_amount);
}
