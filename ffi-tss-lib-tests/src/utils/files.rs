use std::fs::File;
use std::io::{BufRead, BufReader, Write};

pub fn write_to_file(data: Vec<String>, filename: &str) {
    let mut file = match File::create(filename) {
        Ok(file) => {
            println!("{} created.", filename);
            file
        }
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    };

    for line in data {
        if let Err(e) = writeln!(file, "{}", line) {
            eprintln!("Failed to write to file: {}", e);
            return;
        }
    }
}

pub fn read_from_file(filename: &str) -> Vec<String> {
    let file = File::open(filename).expect("Failed to open file");
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| line.expect("Failed to read line"))
        .collect()
}
