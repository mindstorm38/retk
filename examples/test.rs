use std::fs::File;
use std::io::Read;
use std::env;

fn main() {

    let file_path = env::var("RETK_EXE_PATH").unwrap();
    let mut file = File::open(file_path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    retk::analyse(&data);

}
