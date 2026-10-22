#pragma once
#include <cstdint>
#include <functional>
#include <string>

namespace aj {

// Expression evaluation (borrowing the "resolve everything in one expression"
// idea from RadDbg Values.cpp and Z0BDbgCli PseudoC).
//
// Grammar:
//   expr   := logor
//   logor  := logand (('||') logand)*
//   logand := cmp (('&&') cmp)*
//   cmp    := or (('=='|'!='|'<='|'>='|'<'|'>') or)*
//   or     := and (('|'|'^') and)*
//   and    := shift ('&' shift)*
//   shift  := add (('<<'|'>>') add)*
//   add    := mul (('+'|'-') mul)*
//   mul    := unary (('*'|'/') unary)*
//   unary  := '-' unary | '~' unary | '[' expr ']' | primary
//   primary:= number | register | symbol | 'module!sym'|'module+0x10' | '(' expr ')'
//
// Numbers: 0x..., decimal, 0n... decimal, ...h hex.
// Deref:   [expr] reads a pointer-sized value at that address.
struct EvalContext {
    std::function<bool(const std::string& reg, uint64_t& out)> read_reg;
    std::function<bool(uint64_t addr, uint64_t& out)> read_ptr;
    std::function<bool(const std::string& name, uint64_t& out)> resolve;
};

bool eval_expr(const std::string& text, const EvalContext& ctx, uint64_t& out,
               std::string& err);

}  // namespace aj
