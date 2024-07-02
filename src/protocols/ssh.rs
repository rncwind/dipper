pub fn is_ssh(payload: Vec<u8>) -> bool {
    // Check for ASCII "SSH"
    payload[0] == 0x53 && payload[1] == 0x53 && payload[2] == 0x48
}
