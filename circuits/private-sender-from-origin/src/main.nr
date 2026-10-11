use bitcoin_relations::part;
fn main(
    packed:pub [Field;23], statement:[u8;685],token:[u8;32],
    previous_statement:[u8;388],previous_vk:[Field;115],previous_proof:[Field;458],
    previous_authorization:[u8;1466],previous_partial:[u8;32],previous_activation_partial:[u8;32],
    previous_server_salt:[u8;32],previous_origin_signature:[u8;64],
    previous_origin_key_point:[u8;64],previous_origin_nonce_point:[u8;64],
    server: [u8;64], server_salt: [u8;32], user: [u8;32], capability: [u8;32],
    mask: [u8;32], mask_salt: [u8;32], masked_share: [u8;32], masked_share_salt: [u8;32],
    funding_salt: [u8;32], funding_output_key: [u8;32], txid: [u8;32], vout: u32, amount: u64,
    destination: [u8;64], fee: u64, delay: u32, backup_salt: [u8;32],
    issuance_digest: [u8;32], bridge_salt: [u8;32], initial: u32, gap: u32, margin: u32,
) {
    packing::bind::<685,23>(statement,packed);
    lineage::handover(statement);
    let cfg=part::<685,224>(statement,461);
    transfer::sender::sender_with_authenticated_funding(part::<685,461>(statement,0),token,server,server_salt,user,capability,mask,mask_salt,masked_share,masked_share_salt,funding_salt,funding_output_key,txid,vout,amount,destination,fee,delay,backup_salt,issuance_digest,bridge_salt,initial,gap,margin);
    assert(part::<685,68>(statement,0)==part::<388,68>(previous_statement,0), "predecessor domain");
    assert(part::<685,32>(statement,68)==part::<388,32>(previous_statement,100), "predecessor state");
    assert(part::<685,32>(statement,205)==part::<388,32>(previous_statement,68), "predecessor funding");
    assert(part::<685,32>(statement,397)==part::<388,32>(previous_statement,132), "predecessor policy");
    lineage::verify_origin_predecessor(previous_statement,previous_authorization,previous_vk,previous_proof,previous_partial,previous_activation_partial,previous_server_salt,previous_origin_key_point,previous_origin_nonce_point,previous_origin_signature,cfg);
    assert(delay==initial, "typed predecessor delay slot");
}
