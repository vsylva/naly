//! Minimal x86 / x86-64 instruction decoder.
//!
//! A detour needs three facts about each stolen instruction: how long it is,
//! where a relative displacement sits (so branches can be re-targeted), and
//! whether it carries a RIP-relative address (so it can be re-based). The rest
//! of the bytes are copied verbatim.
//!
//! Unknown encodings are reported instead of guessed: a wrong length would
//! corrupt the trampoline, a clean error only costs the hook.

use crate::Error;

/// Longest legal x86 instruction.
pub(crate) const MAX_LEN: usize = 15;

/// How an instruction moves the instruction pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rel {
    /// `jmp rel8`
    Jmp8,
    /// `jcc rel8`, carrying the condition code (`0..=15`)
    Jcc8(u8),
    /// `jmp rel32`
    Jmp32,
    /// `jcc rel32`, carrying the condition code
    Jcc32(u8),
    /// `call rel32`
    Call32,
    /// `loop` / `loope` / `loopne` / `jecxz`: no near encoding exists
    Loop8,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Insn {
    pub(crate) len:      usize,
    pub(crate) rel:      Option<Rel>,
    /// Offset of a relative displacement inside the instruction.
    pub(crate) disp_off: usize,
    /// Offset of a RIP-relative `disp32` (x86-64 only).
    pub(crate) rip_off:  Option<usize>,
    /// True when control never falls through: the function ends here.
    pub(crate) ends:     bool,
}

impl Insn {
    pub(crate) const ZERO: Insn =
        Insn { len: 0, rel: None, disp_off: 0, rip_off: None, ends: false, };
}

/// Decode one instruction from the front of `code`.
///
/// `wide` selects 64-bit operand/address defaults (REX, RIP-relative
/// addressing, 64-bit immediates).
pub(crate) fn decode(code: &[u8], wide: bool) -> Result<Insn, Error> {
    let mut i = 0usize;
    let mut opsize = false;
    let mut addrsize = false;
    let mut rex = 0u8;

    // legacy prefixes; REX must be adjacent to the opcode, but treating a stray
    // second REX as another prefix byte is harmless for length purposes
    while i < code.len() {
        let b = code[i];
        match b {
            0x66 => opsize = true,
            0x67 => addrsize = true,
            0x40..=0x4F if wide => rex = b,
            0xF0 | 0xF2 | 0xF3 | 0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 => {}
            _ => break,
        }
        i += 1;
    }
    if i >= code.len()
    {
        return Err(Error::Truncated);
    }

    let zimm = if opsize { 2 } else { 4 };
    let mut imm = 0usize;
    let mut modrm = false;
    let mut rel: Option<Rel> = None;
    let mut disp_off = 0usize;
    let mut ends = false;

    let op = code[i];
    i += 1;

    if op == 0x0F
    {
        if i >= code.len()
        {
            return Err(Error::Truncated);
        }
        let op2 = code[i];
        i += 1;
        match op2
        {
            // complete instructions without an operand byte
            0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x0E => {}
            0x0B => ends = true, // ud2
            0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x37 => {}
            0x77 => {}
            0xA0 | 0xA1 | 0xA2 | 0xA8 | 0xA9 | 0xAA => {}
            0xC8..=0xCF => {}
            0x80..=0x8F =>
            {
                rel = Some(Rel::Jcc32(op2 & 0x0F));
                disp_off = i;
                imm = 4;
            }
            0x38 =>
            {
                if i >= code.len()
                {
                    return Err(Error::Truncated);
                }
                i += 1;
                modrm = true;
            }
            0x3A =>
            {
                if i >= code.len()
                {
                    return Err(Error::Truncated);
                }
                i += 1;
                modrm = true;
                imm = 1;
            }
            0x0F | 0x70..=0x73 | 0xA4 | 0xAC | 0xBA | 0xC2 | 0xC4 | 0xC5 | 0xC6 =>
            {
                modrm = true;
                imm = 1;
            }
            _ => modrm = true,
        }
    }
    else
    {
        match op
        {
            // add/or/adc/sbb/and/sub/xor/cmp r/m,r and their short forms
            0x00..=0x3F => match op & 7
            {
                0..=3 => modrm = true,
                4 => imm = 1,
                5 => imm = zimm,
                _ => {}
            },
            0x40..=0x4F => {}                 // inc/dec r32 (REX was taken above)
            0x50..=0x5F => {}                 // push/pop r32
            0x60 | 0x61 => {}                 // pusha/popa
            0x62 if wide => return Err(Error::Unsupported { opcode: op }),
            0x62 | 0x63 => modrm = true,      // bound / arpl / movsxd
            0x68 => imm = zimm,               // push imm32
            0x69 => { modrm = true; imm = zimm; }
            0x6A => imm = 1,
            0x6B => { modrm = true; imm = 1; }
            0x6C..=0x6F => {}                 // in/out string forms
            0x70..=0x7F =>
            {
                rel = Some(Rel::Jcc8(op & 0x0F));
                disp_off = i;
                imm = 1;
            }
            0x80 | 0x82 => { modrm = true; imm = 1; }
            0x81 => { modrm = true; imm = zimm; }
            0x83 => { modrm = true; imm = 1; }
            0x84..=0x8F => modrm = true,
            0x90..=0x97 => {}                 // nop / xchg r,eax
            0x98 | 0x99 => {}                 // cbw..cqo / cwd..cqo
            0x9A =>
            {
                if wide
                {
                    return Err(Error::Unsupported { opcode: op });
                }
                imm = 6;
            }
            0x9B..=0x9F => {}
            0xA0..=0xA3 => imm = if wide { if addrsize { 4 } else { 8 } } else if addrsize { 2 } else { 4 },
            0xA4..=0xA7 | 0xAA..=0xAF => {}
            0xA8 => imm = 1,
            0xA9 => imm = zimm,
            0xB0..=0xB7 => imm = 1,
            0xB8..=0xBF => imm = if wide && rex & 0x08 != 0 { 8 } else { zimm },
            0xC0 | 0xC1 => { modrm = true; imm = 1; }
            0xC2 => { imm = 2; ends = true; }
            0xC3 => ends = true,
            0xC4 | 0xC5 =>
            {
                if wide
                {
                    return Err(Error::Unsupported { opcode: op }); // VEX
                }
                modrm = true;
            }
            0xC6 => { modrm = true; imm = 1; }
            0xC7 => { modrm = true; imm = zimm; }
            0xC8 => imm = 3,                  // enter iw, ib
            0xC9 => {}
            0xCA => { imm = 2; ends = true; }
            0xCB | 0xCC | 0xCF => ends = true,
            0xCE => {}
            0xCD => imm = 1,
            0xD0..=0xD3 => modrm = true,
            0xD4 | 0xD5 => imm = 1,
            0xD6 | 0xD7 => {}
            0xD8..=0xDF => modrm = true,      // x87
            0xE0..=0xE3 =>
            {
                rel = Some(Rel::Loop8);
                disp_off = i;
                imm = 1;
            }
            0xE4..=0xE7 => imm = 1,
            0xE8 => { rel = Some(Rel::Call32); disp_off = i; imm = 4; }
            0xE9 => { rel = Some(Rel::Jmp32); disp_off = i; imm = 4; ends = true; }
            0xEA =>
            {
                if wide
                {
                    return Err(Error::Unsupported { opcode: op });
                }
                imm = 6;
            }
            0xEB => { rel = Some(Rel::Jmp8); disp_off = i; imm = 1; ends = true; }
            0xEC..=0xEF => {}
            0xF1 | 0xF5 => {}
            0xF4 => ends = true, // hlt
            0xF6 | 0xF7 => modrm = true,      // immediate depends on the reg field
            0xF8..=0xFD => {}
            0xFE | 0xFF => modrm = true,
            _ => return Err(Error::Unsupported { opcode: op }),
        }
    }

    let mut rip_off = None;
    if modrm
    {
        if i >= code.len()
        {
            return Err(Error::Truncated);
        }
        let m = code[i];
        i += 1;
        let md = m >> 6;
        let reg = (m >> 3) & 7;
        let rm = m & 7;
        if md != 3
        {
            if !wide && addrsize
            {
                // 16-bit addressing
                match md
                {
                    0 =>
                    {
                        if rm == 6
                        {
                            i += 2;
                        }
                    }
                    1 => i += 1,
                    2 => i += 2,
                    _ => {}
                }
            }
            else
            {
                let mut disp = match md
                {
                    1 => 1,
                    2 => 4,
                    _ => 0,
                };
                if rm == 4
                {
                    if i >= code.len()
                    {
                        return Err(Error::Truncated);
                    }
                    let sib = code[i];
                    i += 1;
                    if md == 0 && sib & 7 == 5
                    {
                        disp = 4;
                    }
                }
                else if md == 0 && rm == 5
                {
                    disp = 4;
                    if wide && !addrsize
                    {
                        rip_off = Some(i);
                    }
                }
                i += disp;
            }
        }
        // group 3: only /0 and /1 (test) carry an immediate
        if op == 0xF6 && reg <= 1
        {
            imm = 1;
        }
        if op == 0xF7 && reg <= 1
        {
            imm = zimm;
        }
        // group 5: /4 and /5 are indirect jumps
        if op == 0xFF && (reg == 4 || reg == 5)
        {
            ends = true;
        }
    }

    let len = i + imm;
    if len > MAX_LEN || len > code.len()
    {
        return Err(Error::Truncated);
    }
    Ok(Insn { len, rel, disp_off, rip_off, ends })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn len(code: &[u8], wide: bool) -> usize {
        decode(code, wide).expect("decode").len
    }

    #[test]
    fn prologues_decode() {
        // x64: push rbp / mov rbp, rsp / sub rsp, 0x28
        assert_eq!(len(&[0x55], true), 1);
        assert_eq!(len(&[0x48, 0x89, 0xE5], true), 3);
        assert_eq!(len(&[0x48, 0x83, 0xEC, 0x28], true), 4);
        // mov qword ptr [rsp+8], rbx
        assert_eq!(len(&[0x48, 0x89, 0x5C, 0x24, 0x08], true), 5);
        // endbr64
        assert_eq!(len(&[0xF3, 0x0F, 0x1E, 0xFA], true), 4);
        // mov rax, imm64
        assert_eq!(len(&[0x48, 0xB8, 1, 2, 3, 4, 5, 6, 7, 8], true), 10);
        // nop dword ptr [rax+rax]
        assert_eq!(len(&[0x0F, 0x1F, 0x44, 0x00, 0x00], true), 5);

        // x86: push ebp / mov ebp, esp / sub esp, 0x100
        assert_eq!(len(&[0x8B, 0xEC], false), 2);
        assert_eq!(len(&[0x81, 0xEC, 0x00, 0x01, 0x00, 0x00], false), 6);
        // 16-bit operand override
        assert_eq!(len(&[0x66, 0x81, 0xEC, 0x00, 0x01], false), 5);
        // mov eax, fs:[0x30]
        assert_eq!(len(&[0x64, 0xA1, 0x30, 0x00, 0x00, 0x00], false), 6);
        // jmp dword ptr [imm32]
        assert_eq!(len(&[0xFF, 0x25, 1, 2, 3, 4], false), 6);
        // ret / pop ebp
        assert_eq!(len(&[0x5D], false), 1);
        assert_eq!(len(&[0xC3], false), 1);
    }

    #[test]
    fn immediates_follow_operand_size() {
        assert_eq!(len(&[0x68, 0, 0, 0, 0], false), 5); // push imm32
        assert!(decode(&[0x68, 0, 0], true).is_err()); // truncated in 64-bit mode
        assert_eq!(len(&[0x66, 0x68, 0, 0], false), 4); // push imm16
        assert_eq!(len(&[0xB8, 1, 2, 3, 4], false), 5); // mov eax, imm32
        assert_eq!(len(&[0xB0, 1], false), 2); // mov al, imm8
        // group 3: test carries an immediate, not/neg/mul do not
        assert_eq!(len(&[0xF7, 0xC0, 0, 0, 0, 0], false), 6);
        assert_eq!(len(&[0xF7, 0xD0], false), 2);
        assert_eq!(len(&[0xF6, 0xC0, 0x01], false), 3);
    }

    #[test]
    fn branches_are_classified() {
        let call = decode(&[0xE8, 0, 0, 0, 0], false).expect("call");
        assert_eq!(call.rel, Some(Rel::Call32));
        assert_eq!(call.len, 5);

        let jmp = decode(&[0xE9, 0, 0, 0, 0], false).expect("jmp");
        assert_eq!(jmp.rel, Some(Rel::Jmp32));

        let short = decode(&[0x75, 0x10], false).expect("jne short");
        assert_eq!(short.rel, Some(Rel::Jcc8(5)));
        assert_eq!(short.disp_off, 1);

        let near = decode(&[0x0F, 0x84, 0x10, 0, 0, 0], false).expect("je near");
        assert_eq!(near.rel, Some(Rel::Jcc32(4)));
        assert_eq!(near.disp_off, 2);

        let jmp8 = decode(&[0xEB, 0x10], true).expect("jmp short");
        assert_eq!(jmp8.rel, Some(Rel::Jmp8));

        assert_eq!(decode(&[0xE2, 0x10], false).expect("loop").rel, Some(Rel::Loop8));
    }

    #[test]
    fn rip_relative_only_on_x64() {
        let wide = decode(&[0x48, 0x8B, 0x05, 0x10, 0, 0, 0], true).expect("mov rax,[rip+x]");
        assert_eq!(wide.len, 7);
        assert_eq!(wide.rip_off, Some(3));

        // the same encoding on x86 is an absolute disp32, not RIP-relative
        let narrow = decode(&[0x8B, 0x05, 0x10, 0, 0, 0], false).expect("mov eax,[abs]");
        assert_eq!(narrow.len, 6);
        assert_eq!(narrow.rip_off, None);

        // ... but the same bytes in 64-bit mode are RIP-relative
        let narrow64 = decode(&[0x8B, 0x05, 0x10, 0, 0, 0], true).expect("mov eax,[rip+x]");
        assert_eq!(narrow64.rip_off, Some(2));
    }

    #[test]
    fn sib_and_registers() {
        // mov eax, [rsp+rax*4+0x10]
        assert_eq!(len(&[0x8B, 0x44, 0xA4, 0x10], true), 4);
        // mov eax, [esp+4]
        assert_eq!(len(&[0x8B, 0x44, 0x24, 0x04], false), 4);
        // mov eax, [ebx*4] (no base)
        assert_eq!(len(&[0x8B, 0x04, 0x9D, 0, 0, 0, 0], false), 7);
    }

    #[test]
    fn unknown_encodings_are_rejected() {
        assert!(matches!(decode(&[0xC4, 0xE2], true), Err(Error::Unsupported { .. })));
        assert!(matches!(decode(&[0x62, 0xF1], true), Err(Error::Unsupported { .. })));
        assert!(matches!(decode(&[0x48], true), Err(Error::Truncated)));
        assert!(matches!(decode(&[0x0F], true), Err(Error::Truncated)));
        assert!(matches!(decode(&[0x8B], true), Err(Error::Truncated)));
    }
}
