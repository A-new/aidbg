#include "engine/disasm.h"

#include <Zydis/Zydis.h>

#include <cstring>

#include "util/strutil.h"

namespace aj {
namespace {

// One decoder/formatter pair per machine mode. Both are cheap to hold.
ZydisDecoder g_dec64;
ZydisFormatter g_fmt64;
bool g_ready64 = false;

ZydisDecoder g_dec32;
ZydisFormatter g_fmt32;
bool g_ready32 = false;

bool init64() {
    if (g_ready64) return true;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&g_dec64, ZYDIS_MACHINE_MODE_LONG_64,
                                       ZYDIS_STACK_WIDTH_64)))
        return false;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&g_fmt64, ZYDIS_FORMATTER_STYLE_INTEL)))
        return false;
    g_ready64 = true;
    return true;
}

bool init32() {
    if (g_ready32) return true;
    // LONG_COMPAT_32 keeps the long-mode paging model but decodes 32-bit code,
    // which is exactly what a WOW64 process executes.
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&g_dec32, ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
                                       ZYDIS_STACK_WIDTH_32)))
        return false;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&g_fmt32, ZYDIS_FORMATTER_STYLE_INTEL)))
        return false;
    g_ready32 = true;
    return true;
}

}  // namespace

bool disasm_init(bool is32) { return is32 ? init32() : init64(); }

bool decode_one(const uint8_t* code, size_t len, uint64_t address, Insn& out, bool is32) {
    out = Insn{};
    if (!disasm_init(is32)) return false;

    const ZydisDecoder& dec = is32 ? g_dec32 : g_dec64;
    const ZydisFormatter& fmt = is32 ? g_fmt32 : g_fmt64;

    ZydisDecodedInstruction zi;
    ZydisDecodedOperand zops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, len, &zi, zops)))
        return false;

    char buf[256] = {0};
    ZydisFormatterFormatInstruction(&fmt, &zi, zops, zi.operand_count_visible, buf,
                                    sizeof(buf), address, nullptr);

    out.address = address;
    out.length = zi.length;
    out.text = buf;
    out.valid = true;
    out.bytes.assign(code, code + zi.length);
    const char* mn = ZydisMnemonicGetString(zi.mnemonic);
    out.mnemonic = mn ? mn : "";

    // split "mnemonic operands"
    std::string full = out.text;
    size_t sp = full.find(' ');
    out.operands = (sp == std::string::npos) ? std::string() : trim(full.substr(sp + 1));

    out.is_call = (zi.meta.category == ZYDIS_CATEGORY_CALL);
    out.is_ret = (zi.meta.category == ZYDIS_CATEGORY_RET);
    out.is_jump = (zi.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
    out.is_cond_jump = (zi.meta.category == ZYDIS_CATEGORY_COND_BR);
    out.is_int = (zi.meta.category == ZYDIS_CATEGORY_INTERRUPT) ||
                 zi.mnemonic == ZYDIS_MNEMONIC_INT3 || zi.mnemonic == ZYDIS_MNEMONIC_UD2;
    out.is_syscall = (zi.meta.category == ZYDIS_CATEGORY_SYSCALL) ||
                     zi.mnemonic == ZYDIS_MNEMONIC_SYSCALL || zi.mnemonic == ZYDIS_MNEMONIC_SYSENTER;
    out.is_loop = zi.mnemonic == ZYDIS_MNEMONIC_LOOP || zi.mnemonic == ZYDIS_MNEMONIC_LOOPE ||
                  zi.mnemonic == ZYDIS_MNEMONIC_LOOPNE;
    out.is_rep = (zi.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE |
                                   ZYDIS_ATTRIB_HAS_REPNE)) != 0;

    for (ZyanU8 i = 0; i < zi.operand_count; ++i) {
        if (zops[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && zops[i].imm.is_relative) {
            out.has_target = true;
            out.target = address + zi.length + (uint64_t)zops[i].imm.value.s;
            break;
        }
    }
    return true;
}

size_t insn_length(const uint8_t* code, size_t len, uint64_t address, bool is32) {
    Insn insn;
    if (!decode_one(code, len, address, insn, is32)) return 0;
    return insn.length;
}

}  // namespace aj
