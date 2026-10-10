// Test-only SHA3-256 reference, independently written for codec comparisons.
// Application code must use its selected hash backend instead.
pub fn sha3(input: &[u8]) -> [u8; 32] {
    const RC: [u64; 24] = [
        0x1,
        0x8082,
        0x800000000000808a,
        0x8000000080008000,
        0x808b,
        0x80000001,
        0x8000000080008081,
        0x8000000000008009,
        0x8a,
        0x88,
        0x80008009,
        0x8000000a,
        0x8000808b,
        0x800000000000008b,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x800a,
        0x800000008000000a,
        0x8000000080008081,
        0x8000000000008080,
        0x80000001,
        0x8000000080008008,
    ];
    const ROT: [u32; 25] = [
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ];
    let mut padded = input.to_vec();
    padded.resize(input.len() + 136 - input.len() % 136, 0);
    padded[input.len()] = 6;
    *padded.last_mut().unwrap() |= 128;
    let mut a = [0_u64; 25];
    for block in padded.chunks_exact(136) {
        for (i, lane) in block.chunks_exact(8).enumerate() {
            a[i] ^= u64::from_le_bytes(lane.try_into().unwrap());
        }
        for rc in RC {
            let mut c = [0_u64; 5];
            for x in 0..5 {
                for y in 0..5 {
                    c[x] ^= a[x + 5 * y];
                }
            }
            for x in 0..5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    a[x + 5 * y] ^= d;
                }
            }
            let mut b = [0_u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
                }
            }
            for x in 0..5 {
                for y in 0..5 {
                    a[x + 5 * y] =
                        b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
                }
            }
            a[0] ^= rc;
        }
    }
    let mut result = [0; 32];
    for i in 0..4 {
        result[8 * i..8 * i + 8].copy_from_slice(&a[i].to_le_bytes());
    }
    result
}

pub fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
pub fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
