use crate::dkls23::utilities::c_types::{
    CSessionData,
};

pub fn print_session_data(session: &CSessionData) {
    println!("parameters->threshold: {}", session.parameters.threshold);
    println!("parameters->share_count: {}", session.parameters.share_count);
    println!("party index: {}", session.party_index);
    println!("session_id_len: {}", session.session_id_len);

    //print!("[ ");
    //for i in 0..session.session_id_len {
    //    print!("{} ", session.session_id[i]);
    //}
    //print!("]\n");
}
