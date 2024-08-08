contract;



// ANCHOR: abi
abi Counter {
    fn seven() -> u64;
    fn zero() -> u64;
}

impl Counter for Contract {

    fn seven() -> u64 {
        7
    }

    fn zero() -> u64 {
        0
    }
}
// ANCHOR_END: counter