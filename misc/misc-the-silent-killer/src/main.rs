use std::net::TcpListener;
use nix::unistd::{fork, ForkResult};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use signal_hook::{consts::SIGCHLD, iterator::Signals};
use std::thread;

pub mod db_reqs;
mod manager;
mod worker;
mod utils;
mod state;
use state::{MyProcess, State};

use crate::utils::assign_process_name;



fn main() -> std::io::Result<()> {
    let ip = "0.0.0.0";
    let port = 4242;
    let manager_ip = "127.0.0.1"; // only local connections for manager
    let manager_port =7777;

    // Avoid zombie processes by handling SIGCHLD
    let mut signals = Signals::new([SIGCHLD])?;
    thread::spawn(move || {
        for sig in signals.forever() {
            println!("Received signal {:?}", sig);
            // Reap all exited children
            loop {
                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::StillAlive) | Err(_) => break,
                    Ok(status) => println!("Reaped child: {:?}", status),
                }
            }
        }
    });
    
    
    
    let listener = TcpListener::bind(format!("{}:{}", manager_ip, manager_port))?;
    println!("Manager server listening on {}:{}", manager_ip, manager_port);
    // Accept only one connection to the manager
    match listener.accept() {
        Ok((stream, _addr)) => {
            drop(listener);
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child, .. }) => {
                    println!("Spawned manager process: {}", child);
                }
                Ok(ForkResult::Child) => {
                    assign_process_name("manager");
                    let mut p = MyProcess::new(State::Manager, stream);
                    p.run();
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("Fork failed: {}", e);
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, "Fork failed for manager connection"));
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to accept manager connection: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Manager connection failed"));
        }
    }

    let listener = TcpListener::bind(format!("{}:{}", ip, port))?;
    println!("Forking server listening on {}:{}", ip, port);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                match unsafe { fork() } {
                    Ok(ForkResult::Parent { child, .. }) => {
                        println!("Spawned worker process: {}", child);
                    }
                    Ok(ForkResult::Child) => {
                        assign_process_name("worker");
                        let mut p = MyProcess::new(State::Worker, stream);
                        p.run();
                    }
                    Err(e) => {
                        eprintln!("Fork failed: {}", e);
                    }
                }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }

    Ok(())
}