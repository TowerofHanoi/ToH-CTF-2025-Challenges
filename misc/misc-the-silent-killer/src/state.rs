use std::net::TcpStream;
use crate::manager;
use crate::utils::assign_process_name;
use crate::worker;

#[derive(Debug, Copy, Clone)]
pub enum State {
    Worker,
    Manager,
}
#[derive(Debug)]
pub struct MyProcess {
    state: State,
    pub stream: TcpStream,
}

impl MyProcess {
    pub fn new(state: State, stream: TcpStream) -> Self {
        MyProcess { state: state, stream: stream}
    }

    pub fn run(&mut self) {
        match self.state {
            State::Worker => {
                println!("Running as worker process.");
                worker::worker(self);
            }
            State::Manager => {
                println!("Running as manager process.");
                let _ = manager::manager(self);
            }
        }
    }

    pub fn upgrade(&mut self) {
        match self.state {
            State::Worker => {
                println!("Upgrading to manager process.");
                assign_process_name("manager");
                self.state = State::Manager;
                self.run();
            }
            State::Manager => {
                println!("Already a manager process, no upgrade needed.");
            }
        }
    }
}