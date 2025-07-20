use nix::libc::exit;

use rand::distr::Alphanumeric;
use rand::Rng;
use crate::db_reqs::{DbKey, DbRequest, DbResponse};
use crate::state::MyProcess;
use crate::utils::map_to_vec;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::collections::HashMap;



pub const MAX_KILLERS_PER_TRANSACTION: usize = 100;

pub fn worker(proc: &mut MyProcess) {


    let banner = "
           
                                                                                                                      
             ▓▓████████████ ▓▓███████████▄    ▓▓█████    
             ▓▓████████████ ▓▓█████████████   ▓▓█████    
             ▓▓█████        ▓▓█████   █████   ▓▓█████    
             ▓▓███████████  ▓▓████████████▀   ▓▓█████    
             ▓▓███████████  ▓▓█████████████▄  ▓▓█████    
             ▓▓█████        ▓▓█████    █████  ▓▓█████    
             ▓▓█████        ▓▓██████████████  ▓▓█████    
             ▓▓█████        ▓▓████████████▀   ▓▓█████    


 ██ ▄█▀ ██▓ ██▓     ██▓    ▓█████  ██▀███    ██████    ▓█████▄  ▄▄▄▄   
 ██▄█▒ ▓██▒▓██▒    ▓██▒    ▓█   ▀ ▓██ ▒ ██▒▒██    ▒    ▒██▀ ██▌▓█████▄ 
▓███▄░ ▒██▒▒██░    ▒██░    ▒███   ▓██ ░▄█ ▒░ ▓██▄      ░██   █▌▒██▒ ▄██
▓██ █▄ ░██░▒██░    ▒██░    ▒▓█  ▄ ▒██▀▀█▄    ▒   ██▒   ░▓█▄   ▌▒██░█▀  
▒██▒ █▄░██░░██████▒░██████▒░▒████▒░██▓ ▒██▒▒██████▒▒   ░▒████▓ ░▓█  ▀█▓
▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░▒ ▒▓▒ ▒ ░    ▒▒▓  ▒ ░▒▓███▀▒
░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░░ ░▒  ░ ░    ░ ▒  ▒ ▒░▒   ░ 
░ ░░ ░  ▒ ░  ░ ░     ░ ░      ░     ░░   ░ ░  ░  ░      ░ ░  ░  ░    ░ 
░  ░    ░      ░  ░    ░  ░   ░  ░   ░           ░        ░     ░      
                                                        ░            ░ 
                                                                       
    ";
    let _ = proc.stream.write_all(banner.as_bytes());
    let _ = proc
        .stream
        .write_all(b"\nWelcome to the Killers Database Management System!\n\n");

    let menu = "
    1. Register a new arrest
    2. Show current transaction
    3. Commit transaction
    4. Exit

Please enter your choice:
> ";

    
    let mut transaction: HashMap<DbKey, String> = HashMap::new();

    loop {
        let _ = proc.stream.write_all(menu.as_bytes());
        let _ = proc.stream.flush();

        let mut choice_buffer = [0u8; 8];
        match proc.stream.read(&mut choice_buffer) {
            Ok(size) => {
                let choice = String::from_utf8_lossy(&choice_buffer[..size]);
                match choice.trim() {
                    "1" => add_killer(proc, &mut transaction),
                    "2" => show_current_transaction(proc, &transaction),
                    "3" => commit_transaction(proc, &mut transaction),
                    "4" => {
                        let _ = proc.stream.write_all(b"Exiting...\n");
                        unsafe { exit(0) };
                        
                    }
                    _ => {
                        let _ = proc
                            .stream
                            .write_all(format!("Invalid choice: [{}], please try again.\n", choice).as_bytes());
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read from stream: {}", e);
                break;
            }
        }
    }
}

fn add_killer(proc: &mut MyProcess, transaction: &mut HashMap<DbKey, String>) {
    if transaction.len() >= MAX_KILLERS_PER_TRANSACTION {
        let _ = proc
            .stream
            .write_all(b"Transaction limit reached. Please commit the current transaction.\n");
        return;
    }
    let name = match get_killer_name(proc) {
        Some(name) => name,
        None => {
            let _ = proc
                .stream
                .write_all(b"Invalid name input. Operation cancelled.\n");
            return;
        }
    };

    let surname = match get_killer_surname(proc) {
        Some(surname) => surname,
        None => {
            let _ = proc
                .stream
                .write_all(b"Invalid surname input. Operation cancelled.\n");
            return;
        }
    };

    let accusations = match get_killer_accusations(proc,&name,&surname) {
        Some(conviction) => conviction,
        None => {
            let _ = proc
                .stream
                .write_all(b"Invalid accusation input. Operation cancelled.\n");
            return;
        }
    };
    let _ = proc
        .stream
        .write_all(b"Added a new arrest in the current transaction\n");
    transaction.insert(
        DbKey {
            name: name.clone(),
            surname: surname.clone(),
        },
        accusations,
    );
    let _ = proc.stream.flush();
}

fn get_killer_name(proc: &mut MyProcess) -> Option<String> {
    let _ = proc.stream.write_all(b"Insert killer name:\n> ");
    let _ = proc.stream.flush();
    let mut name_buffer = [0u8; 30];
    match proc.stream.read(&mut name_buffer) {
        Ok(size) => {
            let name = String::from_utf8_lossy(&name_buffer[..size])
                .trim()
                .to_string();
            if !name.is_empty() {
                Some(name)
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!("Failed to read name: {}", e);
            None
        }
    }
}

fn get_killer_surname(proc: &mut MyProcess) -> Option<String> {
    let _ = proc.stream.write_all(b"Insert killer surname:\n> ");
    let _ = proc.stream.flush();
    let mut surname_buffer = [0u8; 30];
    match proc.stream.read(&mut surname_buffer) {
        Ok(size) => {
            let surname = String::from_utf8_lossy(&surname_buffer[..size])
                .trim()
                .to_string();
            if !surname.is_empty() {
                Some(surname)
            } else {
                None
            }
        }
        Err(e) => {
            eprintln!("Failed to read surname: {}", e);
            None
        }
    }
}

fn get_killer_accusations(proc: &mut MyProcess, name: &str, surname: &str) -> Option<String> {

    let _ = proc.stream.write_all("Please insert the legal form type:\n> ".as_bytes());
    let _ = proc.stream.flush();
    let form_type: String;
    let mut form_type_buffer = [0u8; 8];
    match proc.stream.read(&mut form_type_buffer) {
        Ok(size) => {
            form_type = String::from_utf8_lossy(&form_type_buffer[..size])
                .trim()
                .to_string();
            if form_type != "SKC-24F" && form_type != "ATF-01X" && form_type != "HR-77A" {
                let _ = proc
                    .stream
                    .write_all(b"Invalid form type. Please use ATF-01X, SKC-24F, or HR-77A.\n");
                return None;
            }
            if form_type.is_empty() {
                let _ = proc
                    .stream
                    .write_all(b"Invalid form type input. Operation cancelled.\n");
                return None;
            }
        }
        Err(e) => {
            eprintln!("Failed to read form type: {}", e);
            return None;
        }
    }



    let mut accusations: Vec<String> = Vec::new();
    let _ = proc
         .stream
         .write_all(b"Insert accusations to generate arrest report (separated by ','): \n");

    
    let _ = proc.stream.write_all(b"> ");
    let _ = proc.stream.flush();

    let mut reader = BufReader::new(&mut proc.stream);
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(size) => {
            if size == 0 {
                return None;
            }
            // Split accusations by comma
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            if parts.is_empty() {
                let _ = proc
                    .stream
                    .write_all(b"No accusations provided. Operation cancelled.\n");
                return None;
            }
            for accusation in parts {
                let conviction = generate_accusation_legal_report(name, surname, accusation, &form_type);
                if conviction.is_empty() {
                    let _ = proc
                        .stream
                        .write_all(b"Failed to generate accusation report. Please try again.\n");
                    return None;
                }
                accusations.push(conviction);
            }
            return Some(accusations.join("\n"));
        }
        Err(e) => {
            eprintln!("Failed to read accusation line: {}", e);
            return None;
        }
    }
    
    }

 


fn show_current_transaction(proc: &mut MyProcess, transaction: &HashMap<DbKey, String>) {
    if transaction.is_empty() {
        let _ = proc.stream.write_all(b"No current transaction.\n");
        let _ = proc.stream.flush();
        return;
    }
    let _ = proc.stream.write_all(b"Killers in current transaction:\n\n");
    for (key, _) in transaction.iter() {
        let response = format!(
            "Name: {}, Surname: {}\n",
            key.name,
            key.surname,
        );
        let _ = proc.stream.write_all(response.as_bytes());
    }
    let _ = proc.stream.flush();
}

fn commit_transaction(proc: &mut MyProcess, transaction: &mut HashMap<DbKey, String>) {
    if transaction.is_empty() {
        let _ = proc.stream.write_all(b"No changes to commit.\n");
        let _ = proc.stream.flush();
        return;
    }
    let _ = proc.stream.write_all(b"Committing transaction...\n");
    let _ = proc.stream.flush();

    
    let _ = proc.stream.write_all(b"Data ready to be sent...\n");
    let _ = proc.stream.flush();
    let db_request = DbRequest::Put(map_to_vec(transaction));
    send_request_to_manager(proc, &db_request);
    transaction.clear();
}

fn upgrade_to_manager(proc: &mut MyProcess) {
    proc.upgrade();
}

fn send_request_to_manager(proc: &mut MyProcess, request: &DbRequest) {
    let request_json = match serde_json::to_string(request) {
        Ok(json) => json,
        Err(_) => {
            let _ = proc.stream.write_all(b"Failed to serialize request.\n");
            return;
        }
    };

    let dbms_stream = TcpStream::connect("127.0.0.1:1337");
    let mut dbms_stream = match dbms_stream {
        Ok(stream) => stream,
        Err(_) => {
            check_manager_liveness(proc);
            return;
        }
    };

    {
        let mut writer = BufWriter::new(&mut dbms_stream);
        if writer.write_all(request_json.as_bytes()).is_err()
            || writer.write_all(b"\n").is_err()
            || writer.flush().is_err()
        {
            let _ = proc.stream.write_all(b"Failed to send request to DBMS.\n");
            return;
        }
    }
    println!("Request sent to DBMS, waiting for response...");

    let mut reader = BufReader::new(&mut dbms_stream);
    let mut response_json = String::new();
    if reader.read_to_string(&mut response_json).is_err() {
        let _ = proc.stream.write_all(b"Failed to read response from DBMS.\n");
        check_manager_liveness(proc);
        return;
    }

    let response: Result<DbResponse, _> = serde_json::from_str(&response_json);
    match response {
        Ok(DbResponse::Ok(_)) => {
            let _ = proc.stream.write_all(b"Transaction completed successfully.\n");
        }
        Ok(DbResponse::Error(err)) => {
            let _ = proc.stream.write_all(format!("Error: {}\n", err).as_bytes());
        }
        Err(_) => {
            let _ = proc.stream.write_all(format!("Failed to parse response from DBMS. Error: {}\n", response_json).as_bytes());
        }
    }
    println!("Response from DBMS");
    let _ = dbms_stream.shutdown(Shutdown::Both);
}


fn check_manager_liveness(proc: &mut MyProcess)  {
    let mut attempts = 0;
    while attempts < 3 {
        match TcpStream::connect("localhost:1337") {
            Ok(stream) => {
                proc.stream = stream;
                let _ = proc.stream.write_all(b"DB Manager still alive.\n");
                let _ = proc.stream.write_all(b"Please try again now.\n");
                let _ = proc.stream.flush();
                return;
            }
            Err(e) => {
                attempts += 1;
                let message = format!(
                    "Attempt {}/3: Failed to connect to manager: {}. Retrying...\n",
                    attempts, e
                );
                let _ = proc.stream.write_all(message.as_bytes());
                let _ = proc.stream.flush();

            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    let _ = proc.stream.write_all(b"DB Manager is down, upgrading to manager process...\n");
    upgrade_to_manager(proc);
}
    

fn generate_case_id() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect()
}

fn generate_accusation_legal_report(name: &str, surname: &str, accuse: &str, form_type: &str) -> String {
    let case_id = generate_case_id();
    let now = chrono::Utc::now();
    let accusation: String;

    if form_type == "ATF-01X" {
        let arrest_date = now.format("%Y-%m-%d T%H:%M:%S").to_string();
        let trial_date = now.checked_add_signed(chrono::Duration::days(60))
                        .unwrap()
                        .format("%Y-%m-%d T%H:%M:%S")
                        .to_string();
        accusation=format!("
================================================================================
||        BUREAU OF ALCOHOL, TOBACCO, FIREARMS AND EXPLOSIVES (ATF)           ||
||             Homicide Conviction Registry - Form ATF-01X                    ||
================================================================================
ATF Case Reference ID: {},
Convict: {} {},
Accusation: {},
Arrest Date: {},
Trial Date: {},
Plea Status: Pending
--------------------------------------------------------------------------------",
                        case_id,
                        name,
                        surname,
                        accuse,
                        arrest_date,
                        trial_date,
                    );
        return accusation;
    } else if form_type == "SKC-24F" {
        let arrest_date = now.format("%Y-%m-%d T%H:%M:%S").to_string();
        accusation=format!("
SERIAL KILLER CONVICTION REGISTRY - Form 24F
========================================== 
Case ID: {},
Name: {} {},
Accusation: {},
Date: {},
Status: Pending
",
                        case_id,
                        name,
                        surname,
                        accuse,
                        arrest_date,
                    );
        return accusation;
    } else if form_type == "HR-77A" {
        let arrest_date = now.format("%Y-%m-%d T%H:%M:%S").to_string();
        let trial_date = now.checked_add_signed(chrono::Duration::days(90))
                        .unwrap()
                        .format("%Y-%m-%d T%H:%M:%S")
                        .to_string();
        let reeval_date = now.checked_add_signed(chrono::Duration::days(365 * 20))
                        .unwrap()
                        .format("%Y-%m-%d T%H:%M:%S")
                        .to_string();

        accusation=format!("
================================================================================
||                   FEDERAL BUREAU OF INVESTIGATION (FBI)                   ||
||            Homicide Conviction Registry - Form HR-77A (Alpha)             ||
================================================================================

FBI Case Reference ID: {}
--------------------------------------------------------------------------------
This document formally registers the **conviction details** of a perpetrator in a homicide case, adhering strictly to **FBI Protocol 77-A, Subsection Zeta, Paragraph 3.1.4**, and subsequent amendments from **Directive 001-Omega**. Data is processed via the \"Crimson Ledger Imputer\" (v. 4.0.0) and cross-referenced with the **National Crime Information Center (NCIC)**. Any discrepancies must be reported to the **Bureau of Post-Conviction Review (BPCR)** within 72 standard hours.
--------------------------------------------------------------------------------

Registered Conviction Data:
Convict ID (CID):             FBI-Convict-{}-{}-{}
Primary Offense Code (POC):   {}
Jurisdictional Authority (JA):United States District Court, Southern District of NY
Arrest Date (AD):             {} (Confirmed via Judicial Seal)
Trial Date (TD):              {} (Projected)
Apprehending Agent ID (AAID): SA-L.K. Bob-7890
Custodial Facility (CF):      ADX Florence, Supermax (Assigned)
Evidence Nexus Ref (ENR):     CaseFile-{}-EvidenceLog.zip
Plea Status (PS):             Trial Not Yet Conducted
Forensic Review Status (FRS): Pending (---% Match)
Digital Trace Sig (DTS):      MD5-1fc00c5f312b5efc513971c04748a0b6 (From Case {})
Psychological Profile (PPT):  Type Gamma (High Risk)
Future Risk Assessment (FRA): Extreme (Recidivism Probability 98.5%)
Mandatory Re-eval (MRD):      {}
Legal Counsel Ref (LCR):      Public Defender's Office - Case {}-PD
--------------------------------------------------------------------------------

**WARNING:** Unauthorized access or alteration of this registry constitutes a **federal felony** under **Title 18 U.S. Code § 1030**. All data is protected by **classified encryption (AES-256)** and continuously monitored by the **FBI Cyber Division**.
================================================================================
",
                        case_id,
                        name,
                        surname,
                        case_id,
                        accuse,
                        arrest_date,
                        trial_date,
                        case_id,
                        case_id,
                        case_id,
                        reeval_date,
                    );
        return accusation;
    } else {
        return String::new();
    }
    
}
