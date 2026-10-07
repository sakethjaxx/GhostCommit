"""Optional tree-sitter symbol extraction for JS/TS/Go.

analyze(ext, src) -> {qualname: {kind, line, end, dump, feat}} in the same shape audit.py builds for Python,
or None when tree-sitter (pip install tree-sitter tree-sitter-language-pack) is missing; audit.py then
falls back to line regexes. # ponytail: node-type tables below cover the common grammars, not every dialect.
"""
import re

LANG = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "tsx", ".go": "go"}
FUNC_T = {"function_declaration", "generator_function_declaration", "method_definition", "method_declaration"}
ARROW_T = {"arrow_function", "function_expression", "function"}
CLASS_T = {"class_declaration", "abstract_class_declaration", "interface_declaration", "enum_declaration", "type_alias_declaration"}
TERMINAL_T = {"return_statement", "throw_statement", "break_statement", "continue_statement"}
_parsers = {}


def _parser(lang):
    if lang not in _parsers:
        try:
            from tree_sitter_language_pack import get_parser

            _parsers[lang] = get_parser(lang)
        except Exception:  # noqa: BLE001 - missing package or grammar: caller falls back
            _parsers[lang] = None
    return _parsers[lang]


def analyze(ext, src):
    lang = LANG.get(ext)
    parser = _parser(lang) if lang else None
    if parser is None or src is None:
        return None
    data = src.encode("utf-8")
    tree = parser.parse(data)  # keep the Tree referenced for the whole call; nodes dangle if it is collected
    root = tree.root_node
    text = lambda n: data[n.start_byte : n.end_byte].decode("utf-8", "replace")
    head = lambda n: data[n.start_byte : min(n.end_byte, n.start_byte + 80)].decode("utf-8", "replace")
    field = lambda n, f: n.child_by_field_name(f)
    out = {}

    def is_symbol(n):
        return n.type in FUNC_T | CLASS_T or (n.type in ARROW_T and n.parent is not None and n.parent.type == "variable_declarator")

    def feat(fn):
        h = sw = rs = gd = st = 0
        stack = list(fn.children)
        while stack:
            n = stack.pop()
            if is_symbol(n):
                continue
            t = n.type
            if t == "catch_clause":
                h += 1
                body = field(n, "body")
                sw += body is not None and not [c for c in body.named_children if c.type != "comment"]
            elif t == "throw_statement":
                rs += 1
            elif t == "call_expression" and (f := field(n, "function")) is not None and text(f) == "panic":
                rs += 1
            elif t == "if_statement":
                cons = field(n, "consequence")
                kids = [c for c in cons.named_children if c.type != "comment"] if cons is not None and cons.type in {"statement_block", "block"} else [cons]
                if kids and kids[-1] is not None and kids[-1].type == "statement_list":  # go nests statements one level deeper
                    kids = [c for c in kids[-1].named_children if c.type != "comment"]
                gd += bool(kids) and kids[-1] is not None and kids[-1].type in TERMINAL_T
            if (t.endswith("_statement") and t not in {"empty_statement", "statement_block"} or t in {"lexical_declaration", "variable_declaration", "short_var_declaration"}) \
                    and not re.search(r"(?i)not implemented|unimplemented|todo", head(n)):
                st += 1
            stack.extend(n.children)
        params = field(fn, "parameters")
        ann = (sum(c.type == "type_annotation" for c in _walk(params)) if params is not None else 0) + (field(fn, "return_type") is not None)
        names, dflt = [], 0
        for c in (params.named_children if params is not None else []):
            if c.type == "comment":
                continue
            m = re.match(r"\.{0,3}[\w$]+", text(c))
            names.append(m[0] if m else text(c)[:10])
            dflt += field(c, "value") is not None or c.type == "assignment_pattern"
        return {"handlers": h, "swallowed": sw, "raises": rs, "guards": gd, "ann": ann, "sig": (names, dflt), "stmts": st}

    def _walk(n):
        stack = [n]
        while stack:
            x = stack.pop()
            yield x
            stack.extend(x.children)

    def sym(kind, n, f):
        return {"kind": kind, "line": n.start_point[0] + 1, "end": n.end_point[0] + 1,
                "dump": "" if f is None else re.sub(r"\s+", "", text(n)), "feat": f}

    def visit(n, prefix):
        t, name, fn = n.type, None, None
        if t in CLASS_T:
            if (c := field(n, "name")) is not None:
                out[prefix + text(c)] = sym("class", n, None)
                prefix += text(c) + "."
        elif t == "method_declaration":  # go: func (r *T) Name(...)
            recv, c = field(n, "receiver"), field(n, "name")
            m = re.search(r"(\w+)\s*\)\s*$", text(recv)) if recv is not None else None
            name, fn = (f"{m[1]}.{text(c)}" if m else text(c)) if c is not None else None, n
        elif t in FUNC_T:
            name, fn = (text(c) if (c := field(n, "name")) is not None else None), n
        elif t == "variable_declarator" and (v := field(n, "value")) is not None and v.type in ARROW_T and (c := field(n, "name")) is not None:
            name, fn = text(c), v
        if name:
            out[prefix + name] = sym("function", fn, feat(fn))
            prefix += name + "."
        for c in n.children:
            visit(c, prefix)

    visit(root, "")
    out["<module>"] = {"kind": "module", "line": 1, "end": 1, "dump": "", "feat": None}
    return out
