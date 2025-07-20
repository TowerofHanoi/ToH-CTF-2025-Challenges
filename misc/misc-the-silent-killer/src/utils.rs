use std::{collections::HashMap, ffi::CString};
use crate::db_reqs::DbKey;
use nix::sys::prctl;

pub fn vec_to_map(vec: Vec<(DbKey, String)>) -> HashMap<DbKey, String> {
    vec.into_iter().collect()
}

pub fn map_to_vec(map: &HashMap<DbKey, String>) -> Vec<(DbKey, String)> {
    map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    
}

pub fn assign_process_name(name: &str) {
    let new_name = CString::new(name).expect("CString::new failed");

    // Set the process name using prctl
    match prctl::set_name(&new_name) {
        Ok(_) => println!("Child process name changed to: {}", new_name.to_str().unwrap()),
        Err(e) => eprintln!("Failed to set child process name: {}", e),
    }
}