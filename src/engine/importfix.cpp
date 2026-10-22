#include "engine/importfix.h"

#include <Zydis/Zydis.h>

#include <cstring>
#include <map>

#include "engine/disasm.h"
#include "util/strutil.h"

namespace aj {

namespace {

bool is_interesting(const ZydisDecodedInstruction& zi) {
    // same set the Wannabe Universal Import Fixer looks at: things that can
    // reach an API pointer through a memory operand
    switch (zi.mnemonic) {
        case ZYDIS_MNEMONIC_CALL:
        case ZYDIS_MNEMONIC_JMP:
        case ZYDIS_MNEMONIC_MOV:
        case ZYDIS_MNEMONIC_LEA:
            return true;
        default:
            return false;
    }
}

}  // namespace

bool scan_import_refs(const ImportFixInput& in, uint64_t start, uint64_t end,
                      std::vector<ImportRef>& out, std::string& err) {
    out.clear();
    if (end <= start) {
        err = "invalid range";
        return false;
    }
    if (!disasm_init(in.is32)) {
        err = "disassembler is not available";
        return false;
    }

    ZydisDecoder dec;
    ZydisDecoderInit(&dec, in.is32 ? ZYDIS_MACHINE_MODE_LONG_COMPAT_32
                                   : ZYDIS_MACHINE_MODE_LONG_64,
                     in.is32 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);

    uint64_t addr = start;
    while (addr < end) {
        uint8_t buf[32] = {0};
        std::string e;
        if (!in.read(addr, buf, sizeof(buf), e)) break;

        ZydisDecodedInstruction zi;
        ZydisDecodedOperand zops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, buf, sizeof(buf), &zi, zops))) {
            ++addr;  // resynchronise on bad bytes
            continue;
        }

        if (is_interesting(zi)) {
            for (ZyanU8 oi = 0; oi < zi.operand_count; ++oi) {
                if (zops[oi].type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
                const ZydisDecodedOperandMem& m = zops[oi].mem;

                bool rip_rel = (m.base == ZYDIS_REGISTER_RIP);
                bool abs = (m.base == ZYDIS_REGISTER_NONE && m.index == ZYDIS_REGISTER_NONE);
                if (!rip_rel && !abs) continue;
                if (!zi.raw.disp.size) continue;

                ImportRef r;
                r.insn_addr = addr;
                r.insn_size = zi.length;
                r.disp_offset = zi.raw.disp.offset;
                r.rip_relative = rip_rel;
                r.mnemonic = ZydisMnemonicGetString(zi.mnemonic)
                                 ? ZydisMnemonicGetString(zi.mnemonic)
                                 : "";
                r.slot_addr = rip_rel ? (addr + zi.length + (uint64_t)zi.raw.disp.value)
                                      : (uint64_t)zi.raw.disp.value;

                // the slot should hold a pointer to a real API
                uint64_t api = 0;
                size_t ps = in.is32 ? 4 : 8;
                if (!in.read(r.slot_addr, &api, ps, e) || !api) continue;
                r.api_addr = api;

                if (in.resolve) {
                    std::string mod, fn;
                    uint64_t ord = 0;
                    if (!in.resolve(api, mod, fn, ord)) continue;  // not an import pointer
                    r.module = mod;
                    r.function = fn;
                    r.ordinal = ord;
                    r.resolved = true;
                }
                out.push_back(std::move(r));
                break;  // one memory operand per instruction is enough
            }
        }
        addr += zi.length;
    }
    return true;
}

bool fix_import_refs(const ImportFixInput& in, const std::vector<ImportRef>& refs,
                     uint64_t new_base, size_t pointer_size, Json& report, std::string& err) {
    report = Json::obj();
    if (refs.empty()) {
        err = "no import references to fix";
        return false;
    }
    if (!pointer_size) pointer_size = in.is32 ? 4 : 8;

    // one table slot per distinct API, in a stable order
    std::map<std::string, size_t> slot_of;
    std::vector<const ImportRef*> unique;
    for (const auto& r : refs) {
        std::string key = r.module + "!" + r.function;
        if (slot_of.count(key)) continue;
        slot_of[key] = unique.size();
        unique.push_back(&r);
    }

    // write the table: each slot holds the real API pointer
    for (size_t i = 0; i < unique.size(); ++i) {
        uint64_t where = new_base + i * pointer_size;
        if (!in.write(where, &unique[i]->api_addr, pointer_size, err)) {
            err = fmt("cannot write the import table at %s: %s", hex8(where).c_str(),
                      err.c_str());
            return false;
        }
    }

    // rewrite every reference to point at its new slot
    size_t patched = 0;
    Json refs_json = Json::arr();
    for (const auto& r : refs) {
        std::string key = r.module + "!" + r.function;
        uint64_t slot = new_base + slot_of[key] * pointer_size;

        int64_t disp;
        if (r.rip_relative) {
            disp = (int64_t)(slot - (r.insn_addr + r.insn_size));
        } else {
            disp = (int64_t)slot;  // absolute [disp32]
        }
        if (disp < -2147483648LL || disp > 2147483647LL) {
            err = fmt("new table at %s is out of range of instruction at %s "
                      "(RIP-relative displacement must fit in 32 bits, i.e. +/-2GB); "
                      "pass an explicit newva closer to the code",
                      hex8(slot).c_str(), hex8(r.insn_addr).c_str());
            return false;
        }
        int32_t d32 = (int32_t)disp;
        if (!in.write(r.insn_addr + r.disp_offset, &d32, sizeof(d32), err)) {
            err = fmt("cannot patch instruction at %s: %s", hex8(r.insn_addr).c_str(),
                      err.c_str());
            return false;
        }
        ++patched;

        Json j = Json::obj();
        j.set_hex("insn", r.insn_addr);
        j.set_hex("old_slot", r.slot_addr);
        j.set_hex("new_slot", slot);
        j.set_str("module", r.module);
        j.set_str("function", r.function);
        refs_json.push(std::move(j));
    }

    Json slots = Json::arr();
    for (size_t i = 0; i < unique.size(); ++i) {
        Json j = Json::obj();
        j.set_hex("slot", new_base + i * pointer_size);
        j.set_hex("api", unique[i]->api_addr);
        j.set_str("module", unique[i]->module);
        j.set_str("function", unique[i]->function);
        slots.push(std::move(j));
    }

    report.set_hex("table_base", new_base);
    report.set_u("unique_imports", unique.size());
    report.set_u("patched_instructions", patched);
    report.set("table", slots);
    report.set("references", refs_json);
    return true;
}

Json import_refs_to_json(const std::vector<ImportRef>& refs) {
    Json arr = Json::arr();
    for (const auto& r : refs) {
        Json j = Json::obj();
        j.set_hex("insn", r.insn_addr);
        j.set_u("insn_size", r.insn_size);
        j.set_str("mnemonic", r.mnemonic);
        j.set_bool("rip_relative", r.rip_relative);
        j.set_hex("slot", r.slot_addr);
        j.set_hex("api", r.api_addr);
        j.set_bool("resolved", r.resolved);
        if (r.resolved) {
            j.set_str("module", r.module);
            j.set_str("function", r.function);
            if (r.ordinal) j.set_u("ordinal", r.ordinal);
        }
        arr.push(std::move(j));
    }
    return arr;
}

std::string import_refs_to_text(const std::vector<ImportRef>& refs) {
    std::string t = fmt("%-18s %-8s %-18s %-18s %s\n", "instruction", "mnem", "slot", "api",
                        "module!function");
    t += std::string(88, '-') + "\n";
    for (const auto& r : refs) {
        t += fmt("%-18s %-8s %-18s %-18s %s\n", hex8(r.insn_addr).c_str(), r.mnemonic.c_str(),
                 hex8(r.slot_addr).c_str(), hex8(r.api_addr).c_str(),
                 r.resolved ? (r.module + "!" + r.function).c_str() : "<unresolved>");
    }
    return t;
}

}  // namespace aj
