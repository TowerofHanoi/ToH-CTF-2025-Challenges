use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::io::{BufReader, BufWriter, Result, Write, Read, BufRead};
use std::fs;
use std::path::Path;
use std::collections::HashMap;


use crate::utils::{vec_to_map};
use crate::db_reqs::{DbKey, DbRequest, DbResponse};
use crate::state::MyProcess;

const DB_FILE: &str = "dbfile.json";
const DBMS_ADDR: &str = "127.0.0.1:1337";
const CACHE_SIZE_LIMIT: usize = 64; // in MB
const FLUSHING_INTERVAL: u64 = 20; // in transactions
static mut TRANSACTION_COUNTER: u64 = 0;

fn client(stream: &mut TcpStream) {
    

    let _ = stream.write_all(b"Welcome to the DB Manager DEBUG console! \n");
    let _ = stream.write_all(b"Available commands: \n");
    let _ = stream.write_all(b"- get <name> <surname>: get killer info\n");
    let _ = stream.write_all(b"- put <name> <surname> <conviction>: insert a killer in the DB\n");
    let _ = stream.write_all(b"- help: Show this help message.\n");
    let _ = stream.write_all(b"- exit: Exit the DEBUG console.\n");
    loop{
        let mut comm = [0; 128]; 
        let _ = stream.write_all(b"Enter command: ");
        match stream.read(&mut comm){
            Ok(0) => {
                println!("Client disconnected.");
                return;
            }
            Ok(_) => {
                let choice = String::from_utf8_lossy(&comm)
                    .trim_matches(char::from(0))
                    .trim()
                    .to_string();
                println!("Received command: {}", choice);
                if choice.starts_with("get") {
                    let parts: Vec<&str> = choice.split_whitespace().collect();
                    if parts.len() < 3 {
                        let _ = stream.write_all(b"Usage: get <name> <surname>\n");
                        continue;
                    }
                    let key = DbKey {
                        name: parts[1].to_string(),
                        surname: parts[2].to_string(),
                    };
                    let request = DbRequest::Get(key);
                    send_request_to_db(stream, request);
                    
                } else if choice.starts_with("put") {
                    let parts: Vec<&str> = choice.split_whitespace().collect();
                    if parts.len() < 4 {
                        let _ = stream.write_all(b"Usage: put <name> <surname> <conviction>\n");
                        continue;
                    }
                    let key = DbKey {
                        name: parts[1].to_string(),
                        surname: parts[2].to_string(),
                    };
                    let conviction = parts[3].to_string();
                    
                    let request = DbRequest::Put(vec![(key, conviction)]);
                    send_request_to_db(stream, request);
                } else 
                if choice == "help" {
                    let _ = stream.write_all(b"Available commands:\n");
                    let _ = stream.write_all(b"- get <name> <surname>: get killer info\n");
                    let _ = stream.write_all(b"- put <name> <surname> <conviction>: insert a killer in the DB\n");
                    let _ = stream.write_all(b"- help: Show this help message.\n");     
                    let _ = stream.write_all(b"- exit: Exit the DEBUG console.\n");
                } else if choice == "exit" {
                    let _ = stream.write_all(b"Exiting DEBUG console...\n");
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                } else {
                    let _ = stream.write_all(b"Unknown command.\n");
                }
            }
            Err(e) => {
                eprintln!("Error reading from stream: {}", e);
            
            }
        }
    }


}

fn send_request_to_db(mut debug_stream: &TcpStream, request: DbRequest) {
    let request_json = match serde_json::to_string(&request) {
        Ok(json) => json,
        Err(_) => {
            let _ = debug_stream.write_all(b"Failed to serialize request.\n");
            return;
        }
    };

    let dbms_stream = TcpStream::connect("127.0.0.1:1337");
    let mut dbms_stream = match dbms_stream {
        Ok(stream) => stream,
        Err(_) => {
            let _ = debug_stream.write_all(b"Failed to connect to DBMS.\n");
            return;
        }
    };

    {
        let mut writer = BufWriter::new(&mut dbms_stream);
        if writer.write_all(request_json.as_bytes()).is_err()
            || writer.write_all(b"\n").is_err()
            || writer.flush().is_err()
        {
            let _ = debug_stream.write_all(b"Failed to send request to DBMS.\n");
            return;
        }
    }
    println!("Request sent to DBMS, waiting for response...");

    let mut reader = BufReader::new(&mut dbms_stream);
    let mut response_json = String::new();
    if reader.read_to_string(&mut response_json).is_err() {
        let _ = debug_stream.write_all(b"Failed to read response from DBMS.\n");
        return;
    }

    let response: std::result::Result<DbResponse, _> = serde_json::from_str(&response_json);
    match response {
        Ok(DbResponse::Ok(data)) => {
            if let Some(data) = data {
                let _ = debug_stream.write_all(format!("{}\n", data).as_bytes());
            } else {
                let _ = debug_stream.write_all(b"Transaction completed successfully.\n");
            }
        }
        Ok(DbResponse::Error(err)) => {
            let _ = debug_stream.write_all(format!("Error: {}\n", err).as_bytes());
        }
        Err(_) => {
            let _ = debug_stream.write_all(b"Failed to parse response from DBMS.\n");
        }
    }
    println!("Response from DBMS");
    let _ = dbms_stream.shutdown(Shutdown::Both);
}


fn handle_transaction(stream: TcpStream, cache: &mut HashMap<DbKey, String>) -> Result<()> {
    println!("Handling transaction on TcpStream...");
    let mut reader = BufReader::new(&stream);
    let mut writer = BufWriter::new(&stream);

    println!("Reading from TcpStream...");
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let request: DbRequest = serde_json::from_str(&line)?;
    let response = match request {
        DbRequest::Get(data) => DbResponse::Ok(
            Some(cache.get(&data).cloned().unwrap_or_else(|| "Not found".to_string(
            ))),
        ),
        DbRequest::Put(data) => {
            println!("Received Put request");
            if exceed_size_limit(cache, &data) {
                print!("Cache size limit exceeded. Cannot add new data.\n");
                drop(data);
                flush_cache_to_disk(cache)?;
                DbResponse::Error("Database size limit reached.".to_string())
            } else {
                println!("Current cache size is within limits, proceeding with Put request.");
                for (key, value) in data {
                    if cache.contains_key(&key) {
                        println!("Warning: Key {:?} already exists in cache, overwriting value.", key);
                    }
                    cache.entry(key).or_insert(value);
                    unsafe { 
                        TRANSACTION_COUNTER+=1;
                        if TRANSACTION_COUNTER % FLUSHING_INTERVAL == 0 {
                            flush_cache_to_disk(cache)?;
                        } 

                    };
                    
                }

                DbResponse::Ok(None)
            }
        }
    };

    println!("Sending response to TcpStream...");
    serde_json::to_writer(&mut writer, &response)?;
    writer.flush()?;

    Ok(())
}

fn dbms(cache: &mut HashMap<DbKey, String>) -> Result<()> {
    let listener = TcpListener::bind(DBMS_ADDR)?;
    println!("DBMS listening on {}", DBMS_ADDR);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_transaction(stream, cache).unwrap_or_else(|e| {
                    eprintln!("Error handling transaction: {}", e);
                });
                
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}

pub fn manager(proc: &mut MyProcess) -> Result<()> {

    let mut cache: HashMap<DbKey, String> = HashMap::new();
    if Path::new(DB_FILE).exists() {
        let file = fs::File::open(DB_FILE)?;
        let reader = BufReader::new(file);
        let vec: Vec<(DbKey, String)> = serde_json::from_reader(reader).unwrap_or_default();
        cache = vec_to_map(vec);
    }

    let mut stream_clone = proc.stream.try_clone().expect("Failed to clone stream");

    let dbms_handle = thread::spawn(move || {
        dbms(&mut cache).unwrap_or_else(|e| {
            eprintln!("DBMS error: {}", e);
        });
    });

    std::thread::sleep(std::time::Duration::from_millis(500)); // Give DBMS time to bind

    let client_handle = thread::spawn(move || {
        client(&mut stream_clone);
    });

    let _ = client_handle.join();
    let _ = dbms_handle.join();

    Ok(())
}

fn exceed_size_limit(cache: &mut HashMap<DbKey, String>, data: &Vec<(DbKey, String)>) -> bool {
    let current_size: usize = cache.iter()
        .map(|(k, v)| k.name.len() + k.surname.len() + v.len())
        .sum();
    println!("Current cache size: {} MB", current_size / (1024 * 1024));

    let new_size: usize = data.iter()
        .map(|(k, v)| k.name.len() + k.surname.len() + v.len())
        .sum();
    println!("New data size: {} bytes", new_size);
    let total_size = current_size + new_size;
    println!("Total size after adding new data: {} bytes", total_size);
    total_size >= CACHE_SIZE_LIMIT * 1024 * 1024 
}

fn flush_cache_to_disk(cache: &HashMap<DbKey, String>) -> Result<()> {
    let vec: Vec<(&DbKey, &String)> = cache.iter().map(|(k, v)| (k, v)).collect();
    let file = fs::File::create(DB_FILE)?;
    serde_json::to_writer(file, &vec)?;
    Ok(())
}