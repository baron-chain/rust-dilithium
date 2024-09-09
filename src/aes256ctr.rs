pub const AES256CTR_BLOCKBYTES: usize = 64;

pub struct Aes256ctrCtx {
    pub sk_exp: [u64; 120],
    pub ivw: [u32; 16],
}

impl Default for Aes256ctrCtx {
    fn default() -> Self {
        Self {
            sk_exp: [0u64; 120],
            ivw: [0u32; 16],
        }
    }
}

fn decode_u32_le(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

fn decode_u32_range_le(v: &mut [u32], src: &[u8]) {
    for (i, chunk) in src.chunks_exact(4).enumerate() {
        v[i] = decode_u32_le(chunk);
    }
}

fn encode_u32_le(dst: &mut [u8], value: u32) {
    dst.copy_from_slice(&value.to_le_bytes());
}

fn encode_u32_range_le(dst: &mut [u8], v: &[u32]) {
    for (i, value) in v.iter().enumerate() {
        encode_u32_le(&mut dst[i * 4..(i + 1) * 4], *value);
    }
}

fn swap_bytes_32(x: u32) -> u32 {
    x.swap_bytes()
}

fn swap_with_mask(mut x: u64, mut y: &mut u64, mask: u64, shift: usize) -> u64 {
    let t = (x & mask) | ((y & mask) << shift);
    *y = ((*y >> shift) & mask) | ((x >> shift) & mask);
    t
}

fn aes_sbox(q: &mut [u64]) {
    let (x0, x1, x2, x3, x4, x5, x6, x7) = (q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]);

    // Top linear transformation
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;

    // Bottom linear transformation
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Output
    q[7] = z0;
    q[6] = z1;
    q[5] = z2;
    q[4] = z3;
    q[3] = z4;
    q[2] = z5;
    q[1] = z6;
    q[0] = z7;
}

fn swap_inplace(x: u64, y: &mut u64, mask: u64, shift: usize) -> u64 {
    swap_with_mask(x, y, mask, shift)
}

fn ortho(q: &mut [u64]) {
    q[0] = swap_inplace(q[0], &mut q[1], 0x5555555555555555, 1);
    q[2] = swap_inplace(q[2], &mut q[3], 0x5555555555555555, 1);
    q[4] = swap_inplace(q[4], &mut q[5], 0x5555555555555555, 1);
    q[6] = swap_inplace(q[6], &mut q[7], 0x5555555555555555, 1);

    q[0] = swap_inplace(q[0], &mut q[2], 0x3333333333333333, 2);
    q[1] = swap_inplace(q[1], &mut q[3], 0x3333333333333333, 2);
    q[4] = swap_inplace(q[4], &mut q[6], 0x3333333333333333, 2);
    q[5] = swap_inplace(q[5], &mut q[7], 0x3333333333333333, 2);

    q[0] = swap_inplace(q[0], &mut q[4], 0x0F0F0F0F0F0F0F0F, 4);
    q[1] = swap_inplace(q[1], &mut q[5], 0x0F0F0F0F0F0F0F0F, 4);
    q[2] = swap_inplace(q[2], &mut q[6], 0x0F0F0F0F0F0F0F0F, 4);
    q[3] = swap_inplace(q[3], &mut q[7], 0x0F0F0F0F0F0F0F0F, 4);
}

fn interleave_in(q0: &mut u64, q1: &mut u64, w: &[u32]) {
    let mut x0 = w[0] as u64;
    let mut x1 = w[1] as u64;
    let mut x2 = w[2] as u64;
    let mut x3 = w[3] as u64;

    x0 |= x0 << 16;
    x1 |= x1 << 16;
    x2 |= x2 << 16;
    x3 |= x3 << 16;

    x0 &= 0x0000FFFF0000FFFFu64;
    x1 &= 0x0000FFFF0000FFFFu64;
    x2 &= 0x0000FFFF0000FFFFu64;
    x3 &= 0x0000FFFF0000FFFFu64;

    x0 |= x0 << 8;
    x1 |= x1 << 8;
    x2 |= x2 << 8;
    x3 |= x3 << 8;

    x0 &= 0x00FF00FF00FF00FFu64;
    x1 &= 0x00FF00FF00FF00FFu64;
    x2 &= 0x00FF00FF00FF00FFu64;
    x3 &= 0x00FF00FF00FF00FFu64;

    *q0 = x0 | (x2 << 8);
    *q1 = x1 | (x3 << 8);
}

fn interleave_out(w: &mut [u32], q0: u64, q1: u64) {
    let mut x0 = q0 & 0x00FF00FF00FF00FFu64;
    let mut x1 = q1 & 0x00FF00FF00FF00FFu64;
    let mut x2 = (q0 >> 8) & 0x00FF00FF00FF00FFu64;
    let mut x3 = (q1 >> 8) & 0x00FF00FF00FF00FFu64;

    x0 |= x0 >> 8;
    x1 |= x1 >> 8;
    x2 |= x2 >> 8;
    x3 |= x3 >> 8;

    x0 &= 0x0000FFFF0000FFFFu64;
    x1 &= 0x0000FFFF0000FFFFu64;
    x2 &= 0x0000FFFF0000FFFFu64;
    x3 &= 0x0000FFFF0000FFFFu64;

    w[0] = (x0 | (x0 >> 16)) as u32;
    w[1] = (x1 | (x1 >> 16)) as u32;
    w[2] = (x2 | (x2 >> 16)) as u32;
    w[3] = (x3 | (x3 >> 16)) as u32;
}

fn sub_word(x: u32) -> u32 {
    let mut q = [0u64; 8];
    q[0] = x as u64;
    ortho(&mut q);
    aes_sbox(&mut q);
    ortho(&mut q);
    q[0] as u32
}

const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

fn aes_keyschedule(comp_skey: &mut [u64], key: &[u8]) {
    let mut skey = [0u32; 60];
    let key_len = 32;
    let nk = key_len / 4;
    let rounds = 14;

    decode_u32_range_le(&mut skey, key);

    let mut tmp = skey[nk - 1];
    for i in nk..(rounds + 1) * 4 {
        if i % nk == 0 {
            tmp = sub_word(tmp.rotate_left(8)) ^ RCON[i / nk - 1];
        } else if nk > 6 && i % nk == 4 {
            tmp = sub_word(tmp);
        }
        skey[i] = skey[i - nk] ^ tmp;
    }

    let mut j = 0;
    for idx in (0..(rounds + 1) * 4).step_by(4) {
        let mut q = [0u64; 8];
        interleave_in(&mut q[0], &mut q[4], &skey[idx..idx + 4]);
        ortho(&mut q);
        comp_skey[j] = q[0];
        comp_skey[j + 1] = q[4];
        j += 2;
    }
}

fn add_round_key(q: &mut [u64], sk: &[u64]) {
    for (q_val, sk_val) in q.iter_mut().zip(sk.iter()) {
        *q_val ^= *sk_val;
    }
}

fn shift_rows(q: &mut [u64]) {
    for x in q.iter_mut() {
        *x = (*x & 0x000000000000FFFF)
            | ((*x & 0x00000000FFF00000) >> 4)
            | ((*x & 0x00000000000F0000) << 12)
            | ((*x & 0x0000FF0000000000) >> 8)
            | ((*x & 0x000000FF00000000) << 8)
            | ((*x & 0xF000000000000000) >> 12)
            | ((*x & 0x0FFF000000000000) << 4);
    }
}

fn rotate_right_32(x: u64) -> u64 {
    x.rotate_right(32)
}

fn mix_columns(q: &mut [u64]) {
    for x in q.iter_mut() {
        *x = x.rotate_right(32) ^ *x;
    }
}

fn increment_counter(ivw: &mut [u32], block_count: u32) {
    for i in (3..16).step_by(4) {
        ivw[i] = swap_bytes_32(swap_bytes_32(ivw[i]).wrapping_add(block_count));
    }
}

fn aes_ctr(out: &mut [u8], ivw: &mut [u32], sk_exp: &[u64]) {
    let mut w = [0u32; 16];
    w.copy_from_slice(&ivw);
    let mut q = [0u64; 8];
    for i in 0..4 {
        interleave_in(&mut q[i], &mut q[i + 4], &w[i * 4..(i + 1) * 4]);
    }
    ortho(&mut q);

    add_round_key(&mut q, sk_exp);
    for i in 1..14 {
        aes_sbox(&mut q);
        shift_rows(&mut q);
        mix_columns(&mut q);
        add_round_key(&mut q, &sk_exp[i * 8..(i + 1) * 8]);
    }
    aes_sbox(&mut q);
    shift_rows(&mut q);
    add_round_key(&mut q, &sk_exp[112..]);

    ortho(&mut q);
    for i in 0..4 {
        interleave_out(&mut w[i * 4..(i + 1) * 4], q[i], q[i + 4]);
    }
    encode_u32_range_le(out, &w);

    increment_counter(ivw, 4);
}

pub fn aes256ctr_init(ctx: &mut Aes256ctrCtx, key: &[u8], nonce: &[u8]) {
    aes_keyschedule(&mut ctx.sk_exp, key);
    decode_u32_range_le(&mut ctx.ivw[0..3], nonce);
    ctx.ivw[3..].copy_from_slice(&[swap_bytes_32(0), swap_bytes_32(1), swap_bytes_32(2), swap_bytes_32(3)]);
}

pub fn aes256ctr_squeeze_blocks(out: &mut [u8], nblocks: u64, ctx: &mut Aes256ctrCtx) {
    for chunk in out.chunks_mut(AES256CTR_BLOCKBYTES).take(nblocks as usize) {
        aes_ctr(chunk, &mut ctx.ivw, &ctx.sk_exp);
    }
}
