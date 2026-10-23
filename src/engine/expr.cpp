#include "engine/expr.h"

#include <cctype>
#include <cstring>
#include <vector>

#include "util/strutil.h"

namespace aj {
namespace {

enum class TokKind { End, Num, Name, Op };

struct Token {
    TokKind kind = TokKind::End;
    uint64_t num = 0;
    std::string text;
};

class Lexer {
public:
    explicit Lexer(const std::string& s) : s_(s) {}
    bool next(Token& t, std::string& err) {
        skip_ws();
        if (pos_ >= s_.size()) {
            t.kind = TokKind::End;
            return true;
        }
        char c = s_[pos_];
        if (std::isdigit((unsigned char)c) ||
            (c == '0' && pos_ + 1 < s_.size() && (s_[pos_ + 1] == 'x' || s_[pos_ + 1] == 'n'))) {
            size_t b = pos_;
            while (pos_ < s_.size() &&
                   (std::isalnum((unsigned char)s_[pos_]) || s_[pos_] == '_'))
                ++pos_;
            std::string lit = s_.substr(b, pos_ - b);
            if (!parse_u64(lit, t.num)) {
                // allow trailing 'h' style already handled by parse_u64
                err = "bad number: " + lit;
                return false;
            }
            t.kind = TokKind::Num;
            return true;
        }
        if (std::isalpha((unsigned char)c) || c == '_' || c == '$' || c == '@' || c == '.') {
            size_t b = pos_;
            while (pos_ < s_.size() &&
                   (std::isalnum((unsigned char)s_[pos_]) || s_[pos_] == '_' ||
                    s_[pos_] == '$' || s_[pos_] == '@' || s_[pos_] == '.' ||
                    s_[pos_] == '!' || s_[pos_] == ':' || s_[pos_] == '?' || s_[pos_] == '*'))
                ++pos_;
            t.text = s_.substr(b, pos_ - b);
            t.kind = TokKind::Name;
            return true;
        }
        // operators, longest match first
        static const char* ops[] = {"<<", ">>", "&&", "||", "==", "!=", ">=", "<=",
                                    "+", "-", "*", "/", "&", "|", "^", "~", "[", "]",
                                    "(", ")", "<", ">"};
        for (const char* op : ops) {
            size_t n = std::strlen(op);
            if (s_.compare(pos_, n, op) == 0) {
                t.kind = TokKind::Op;
                t.text = op;
                pos_ += n;
                return true;
            }
        }
        err = fmt("unexpected character '%c'", c);
        return false;
    }

private:
    void skip_ws() {
        while (pos_ < s_.size() && std::isspace((unsigned char)s_[pos_])) ++pos_;
    }
    const std::string& s_;
    size_t pos_ = 0;
};

struct Parser {
    Lexer lex;
    Token cur;
    std::string err;
    const EvalContext& ctx;

    Parser(const std::string& s, const EvalContext& c) : lex(s), ctx(c) {}

    bool advance() { return lex.next(cur, err); }
    bool is_op(const char* o) const {
        return cur.kind == TokKind::Op && cur.text == o;
    }

    bool parse(uint64_t& out) {
        if (!advance()) return false;
        if (!log_or(out)) return false;
        if (cur.kind != TokKind::End) {
            err = "trailing input: " + cur.text;
            return false;
        }
        return true;
    }

    bool log_or(uint64_t& out) {
        if (!log_and(out)) return false;
        while (is_op("||")) {
            if (!advance()) return false;
            uint64_t rhs;
            if (!log_and(rhs)) return false;
            out = (out || rhs) ? 1 : 0;
        }
        return true;
    }

    bool log_and(uint64_t& out) {
        if (!cmp_expr(out)) return false;
        while (is_op("&&")) {
            if (!advance()) return false;
            uint64_t rhs;
            if (!cmp_expr(rhs)) return false;
            out = (out && rhs) ? 1 : 0;
        }
        return true;
    }

    bool cmp_expr(uint64_t& out) {
        if (!or_expr(out)) return false;
        while (cur.kind == TokKind::Op &&
               (cur.text == "==" || cur.text == "!=" || cur.text == "<=" || cur.text == ">=" ||
                cur.text == "<" || cur.text == ">")) {
            std::string op = cur.text;
            if (!advance()) return false;
            uint64_t rhs;
            if (!or_expr(rhs)) return false;
            bool r;
            if (op == "==") {
                r = out == rhs;
            } else if (op == "!=") {
                r = out != rhs;
            } else {
                int64_t a = (int64_t)out, b = (int64_t)rhs;
                if (op == "<=")
                    r = a <= b;
                else if (op == ">=")
                    r = a >= b;
                else if (op == "<")
                    r = a < b;
                else
                    r = a > b;
            }
            out = r ? 1 : 0;
        }
        return true;
    }

    bool or_expr(uint64_t& out) {
        if (!and_expr(out)) return false;
        while (is_op("|") || is_op("^")) {
            std::string op = cur.text;
            if (!advance()) return false;
            uint64_t rhs;
            if (!and_expr(rhs)) return false;
            out = (op == "|") ? (out | rhs) : (out ^ rhs);
        }
        return true;
    }
    bool and_expr(uint64_t& out) {
        if (!shift_expr(out)) return false;
        while (is_op("&")) {
            if (!advance()) return false;
            uint64_t rhs;
            if (!shift_expr(rhs)) return false;
            out &= rhs;
        }
        return true;
    }
    bool shift_expr(uint64_t& out) {
        if (!add_expr(out)) return false;
        while (is_op("<<") || is_op(">>")) {
            std::string op = cur.text;
            if (!advance()) return false;
            uint64_t rhs;
            if (!add_expr(rhs)) return false;
            out = (op == "<<") ? (out << (rhs & 63)) : (out >> (rhs & 63));
        }
        return true;
    }
    bool add_expr(uint64_t& out) {
        if (!mul_expr(out)) return false;
        while (is_op("+") || is_op("-")) {
            std::string op = cur.text;
            if (!advance()) return false;
            uint64_t rhs;
            if (!mul_expr(rhs)) return false;
            out = (op == "+") ? (out + rhs) : (out - rhs);
        }
        return true;
    }
    bool mul_expr(uint64_t& out) {
        if (!unary(out)) return false;
        while (is_op("*") || is_op("/")) {
            std::string op = cur.text;
            if (!advance()) return false;
            uint64_t rhs;
            if (!unary(rhs)) return false;
            if (op == "*") {
                out *= rhs;
            } else {
                if (rhs == 0) {
                    err = "division by zero";
                    return false;
                }
                out /= rhs;
            }
        }
        return true;
    }

    bool unary(uint64_t& out) {
        if (is_op("-")) {
            if (!advance()) return false;
            uint64_t v;
            if (!unary(v)) return false;
            out = (uint64_t)(-(int64_t)v);
            return true;
        }
        if (is_op("~")) {
            if (!advance()) return false;
            uint64_t v;
            if (!unary(v)) return false;
            out = ~v;
            return true;
        }
        return primary(out);
    }

    bool primary(uint64_t& out) {
        if (cur.kind == TokKind::Num) {
            out = cur.num;
            return advance();
        }
        if (is_op("(")) {
            if (!advance()) return false;
            if (!log_or(out)) return false;
            if (!is_op(")")) {
                err = "expected ')'";
                return false;
            }
            return advance();
        }
        if (is_op("[")) {
            if (!advance()) return false;
            uint64_t addr;
            if (!log_or(addr)) return false;
            if (!is_op("]")) {
                err = "expected ']'";
                return false;
            }
            if (!advance()) return false;
            if (!ctx.read_ptr) {
                err = "dereference not available";
                return false;
            }
            if (!ctx.read_ptr(addr, out)) {
                err = fmt("cannot read memory at %s", hex8(addr).c_str());
                return false;
            }
            return true;
        }
        if (cur.kind == TokKind::Name) {
            std::string name = cur.text;
            if (!advance()) return false;
            // register?
            if (ctx.read_reg) {
                uint64_t v;
                std::string rn = name;
                if (!rn.empty() && rn[0] == '$') rn = rn.substr(1);
                if (ctx.read_reg(rn, v)) {
                    out = v;
                    return true;
                }
            }
            if (ctx.resolve) {
                uint64_t v;
                if (ctx.resolve(name, v)) {
                    out = v;
                    return true;
                }
            }
            err = "unknown symbol or register: " + name;
            return false;
        }
        err = cur.kind == TokKind::End ? "unexpected end of expression"
                                       : ("unexpected token: " + cur.text);
        return false;
    }
};

}  // namespace

bool eval_expr(const std::string& text, const EvalContext& ctx, uint64_t& out,
               std::string& err) {
    std::string t = trim(text);
    if (t.empty()) {
        err = "empty expression";
        return false;
    }
    Parser p(t, ctx);
    bool ok = p.parse(out);
    if (!ok && err.empty()) err = p.err.empty() ? "invalid expression" : p.err;
    return ok;
}

}  // namespace aj
