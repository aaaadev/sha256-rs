//! sha256-rs
//!
//! Implementation of the SHA256 hash made using Rust

/// Initializing Variables
/// First 32 bits of fractional parts of the square roots of the first eight primes
const H0: u32 = 0x6a09e667;
const H1: u32 = 0xbb67ae85;
const H2: u32 = 0x3c6ef372;
const H3: u32 = 0xa54ff53a;
const H4: u32 = 0x510e527f;
const H5: u32 = 0x9b05688c;
const H6: u32 = 0x1f83d9ab;
const H7: u32 = 0x5be0cd19;

/// Constants table
/// First 32 bits of the fractional parts of the cube roots of the first 64 primes
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Encode string
pub fn sha256(string: &str) -> String {
    let mut result = String::new();

    let mut bytes = string.as_bytes().to_vec();
    let bytes_len = bytes.len() * 8;
    bytes.push(0x80);

    while (bytes.len() % 64) != 56 {
        bytes.push(0);
    }

    for i in bytes_len.to_be_bytes().iter() {
        bytes.push(*i);
    }

    for chunk in bytes.as_slice().chunks(64) {
        let mut w = [0; 64];

        for (w, d) in w.iter_mut().zip(chunk.iter().step_by(4)).take(16) {
            *w = u32::from_be_bytes(unsafe { *(d as *const u8 as *const [u8; 4]) });
        }

        for i in 16..64 {
            let s0: u32 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1: u32 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = H0;
        let mut b = H1;
        let mut c = H2;
        let mut d = H3;
        let mut e = H4;
        let mut f = H5;
        let mut g = H6;
        let mut h = H7;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        let res0 = H0.wrapping_add(a);
        let res1 = H1.wrapping_add(b);
        let res2 = H2.wrapping_add(c);
        let res3 = H3.wrapping_add(d);
        let res4 = H4.wrapping_add(e);
        let res5 = H5.wrapping_add(f);
        let res6 = H6.wrapping_add(g);
        let res7 = H7.wrapping_add(h);

        result = format!(
            "{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            res0, res1, res2, res3, res4, res5, res6, res7
        )
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(
            sha256("Test"),
            String::from("532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25")
        );

        assert_eq!(
            sha256("Rust"),
            String::from("d9aa89fdd15ad5c41d9c128feffe9e07dc828b83f85296f7f42bda506821300e")
        );

        assert_eq!(
            sha256("hello world"),
            String::from("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        );

        assert_eq!(
            sha256("Lorem ipsum dolor sit amet, consectetur adipiscing elit"),
            String::from("07fe4d4a25718241af145a93f890eb5469052e251d199d173bd3bd50c3bb4da2")
        );
    }
}
