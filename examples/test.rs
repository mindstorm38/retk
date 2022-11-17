use std::fs::File;
use std::io::Read;

fn main() {

    let mut file = File::open(r"C:\Games\World_of_Tanks_EU\reverse\1.18.1.2\WorldOfTanks.exe").unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    retk::analyse(&data);

}
