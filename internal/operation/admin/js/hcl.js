/**
 * js/hcl.js
 *
 * HCL2 lexer, parser, formatter, and syntax highlighter.
 * Pure JS — no dependencies, no eval. CSP-safe.
 *
 * Usage:
 *   import { formatHCL, highlightHCL, parseHCL, validateHCL } from './hcl.js';
 *
 *   formatHCL(rawString)        → formatted HCL string (throws on syntax error)
 *   highlightHCL(rawString)     → HTML string with <span class="hcl-*"> tags
 *   parseHCL(rawString)         → { success, data, error }
 *   validateHCL(rawString)      → null if valid, error string if invalid
 */


const TT = {
    IDENTIFIER:'IDENTIFIER', STRING:'STRING', NUMBER:'NUMBER',
    BOOLEAN:'BOOLEAN', NULL:'NULL',
    EQUALS:'EQUALS', COLON:'COLON',
    LBRACE:'LBRACE', RBRACE:'RBRACE', LBRACKET:'LBRACKET', RBRACKET:'RBRACKET',
    LPAREN:'LPAREN', RPAREN:'RPAREN',
    COMMA:'COMMA', DOT:'DOT',
    PLUS:'PLUS', MINUS:'MINUS', STAR:'STAR', SLASH:'SLASH', PERCENT:'PERCENT',
    EQ:'EQ', NEQ:'NEQ', LT:'LT', GT:'GT', LTE:'LTE', GTE:'GTE',
    AND:'AND', OR:'OR', NOT:'NOT',
    QUESTION:'QUESTION', ELLIPSIS:'ELLIPSIS', ARROW:'ARROW',
    TEMPLATE_START:'TEMPLATE_START',
    COMMENT:'COMMENT', BLOCK_COMMENT:'BLOCK_COMMENT',
    NEWLINE:'NEWLINE', EOF:'EOF',
};

class _Token {
    constructor(type, value, line, col, raw) {
        this.type = type; this.value = value;
        this.line = line; this.column = col;
        this.raw  = raw ?? String(value ?? '');
    }
}


class _Lexer {
    constructor(src) {
        this.src = src; this.pos = 0; this.line = 1; this.col = 1;
    }

    next() {
        this._skipWS();
        if (this.pos >= this.src.length)
            return new _Token(TT.EOF, null, this.line, this.col, '');

        const ch = this.src[this.pos];
        const sl = this.line, sc = this.col;

        // Comments
        if (ch === '#' || (ch === '/' && this._peek() === '/'))  return this._comment(sl, sc);
        if (ch === '/' && this._peek() === '*')                  return this._blockComment(sl, sc);

        // Heredoc
        if (ch === '<' && this._peek() === '<')                  return this._heredoc(sl, sc);

        // Template ${
        if (ch === '$' && this._peek() === '{') {
            this.pos += 2; this.col += 2;
            return new _Token(TT.TEMPLATE_START, '${', sl, sc, '${');
        }

        // String
        if (ch === '"') return this._string(sl, sc);

        // Number
        if (this._isDigit(ch) || (ch === '-' && this._isDigit(this._peek())))
            return this._number(sl, sc);

        // Identifier / keyword
        if (this._isLetter(ch) || ch === '_') return this._ident(sl, sc);

        // Two-char ops
        const two = ch + (this._peek() || '');
        const twoOps = {'==':TT.EQ,'!=':TT.NEQ,'<=':TT.LTE,'>=':TT.GTE,'&&':TT.AND,'||':TT.OR,'=>':TT.ARROW};
        if (twoOps[two]) { this.pos += 2; this.col += 2; return new _Token(twoOps[two], two, sl, sc, two); }

        if (ch + (this._peek()||'') + (this._peek(2)||'') === '...') {
            this.pos += 3; this.col += 3;
            return new _Token(TT.ELLIPSIS, '...', sl, sc, '...');
        }

        // Single-char
        this.pos++; this.col++;
        const singles = {
            '=':TT.EQUALS,':':TT.COLON,'{':TT.LBRACE,'}':TT.RBRACE,
            '[':TT.LBRACKET,']':TT.RBRACKET,'(':TT.LPAREN,')':TT.RPAREN,
            ',':TT.COMMA,'.':TT.DOT,'+':TT.PLUS,'-':TT.MINUS,'*':TT.STAR,
            '/':TT.SLASH,'%':TT.PERCENT,'<':TT.LT,'>':TT.GT,'!':TT.NOT,'?':TT.QUESTION,
        };
        if (singles[ch]) return new _Token(singles[ch], ch, sl, sc, ch);

        if (ch === '\n') { this.line++; this.col = 1; return new _Token(TT.NEWLINE, '\n', sl, sc, '\n'); }

        throw new Error(`Unexpected '${ch}' at line ${sl}:${sc}`);
    }

    _peek(n = 1) { return this.src[this.pos + n] ?? null; }

    _skipWS() {
        while (this.pos < this.src.length) {
            const c = this.src[this.pos];
            if (c === ' ' || c === '\t' || c === '\r') { this.pos++; this.col++; }
            else break;
        }
    }

    _comment(l, c) {
        const s = this.pos;
        const start = this.src[this.pos];
        if (start === '/' && this._peek() === '/') { this.pos += 2; this.col += 2; }
        else { this.pos++; this.col++; }
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') { this.pos++; this.col++; }
        const v = this.src.slice(s, this.pos);
        return new _Token(TT.COMMENT, v, l, c, v);
    }

    _blockComment(l, c) {
        const s = this.pos; this.pos += 2; this.col += 2;
        while (this.pos < this.src.length - 1) {
            if (this.src[this.pos] === '*' && this.src[this.pos+1] === '/') { this.pos += 2; this.col += 2; break; }
            if (this.src[this.pos] === '\n') { this.line++; this.col = 1; } else { this.col++; }
            this.pos++;
        }
        const v = this.src.slice(s, this.pos);
        return new _Token(TT.BLOCK_COMMENT, v, l, c, v);
    }

    _heredoc(l, c) {
        const s = this.pos; this.pos += 2; this.col += 2;
        let indented = false;
        if (this.src[this.pos] === '-') { indented = true; this.pos++; this.col++; }
        const ds = this.pos;
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') { this.pos++; this.col++; }
        const delim = this.src.slice(ds, this.pos).trim();
        if (this.pos < this.src.length) { this.pos++; this.line++; this.col = 1; }
        const lines = [];
        while (this.pos < this.src.length) {
            const lineStart = this.pos;
            while (this.pos < this.src.length && this.src[this.pos] !== '\n') this.pos++;
            const line = this.src.slice(lineStart, this.pos).trimEnd();
            if (line.trim() === delim) { if (this.pos < this.src.length) { this.pos++; this.line++; this.col = 1; } break; }
            lines.push(line);
            if (this.pos < this.src.length) { this.pos++; this.line++; this.col = 1; }
        }
        let content = lines.join('\n');
        if (indented) {
            const min = Math.min(...lines.filter(l => l.trim()).map(l => l.match(/^(\s*)/)[1].length));
            content = lines.map(l => l.slice(min)).join('\n');
        }
        return new _Token(TT.STRING, content, l, c, this.src.slice(s, this.pos));
    }

    _string(l, c) {
        const s = this.pos; this.pos++; this.col++;
        let v = '';
        while (this.pos < this.src.length) {
            const ch = this.src[this.pos];
            if (ch === '"') { this.pos++; this.col++; break; }
            if (ch === '\\') {
                this.pos++; this.col++;
                const e = this.src[this.pos];
                const esc = {n:'\n',t:'\t',r:'\r','"':'"','\\':'\\'};
                v += esc[e] ?? e;
            } else { v += ch; }
            this.pos++; this.col++;
        }
        return new _Token(TT.STRING, v, l, c, this.src.slice(s, this.pos));
    }

    _number(l, c) {
        const s = this.pos;
        if (this.src[this.pos] === '-') { this.pos++; this.col++; }
        while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) { this.pos++; this.col++; }
        if (this.src[this.pos] === '.' && this._isDigit(this._peek())) {
            this.pos++; this.col++;
            while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) { this.pos++; this.col++; }
        }
        if ('eE'.includes(this.src[this.pos])) {
            this.pos++; this.col++;
            if ('+-'.includes(this.src[this.pos])) { this.pos++; this.col++; }
            while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) { this.pos++; this.col++; }
        }
        const raw = this.src.slice(s, this.pos);
        return new _Token(TT.NUMBER, parseFloat(raw), l, c, raw);
    }

    _ident(l, c) {
        const s = this.pos;
        while (this.pos < this.src.length &&
        (this._isLetter(this.src[this.pos]) || this._isDigit(this.src[this.pos]) ||
            '_-'.includes(this.src[this.pos]))) { this.pos++; this.col++; }
        const raw = this.src.slice(s, this.pos);
        if (raw === 'true' || raw === 'false') return new _Token(TT.BOOLEAN, raw === 'true', l, c, raw);
        if (raw === 'null')                    return new _Token(TT.NULL, null, l, c, raw);
        return new _Token(TT.IDENTIFIER, raw, l, c, raw);
    }

    _isDigit(ch) { return ch >= '0' && ch <= '9'; }
    _isLetter(ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); }
}


function _tokenise(src) {
    const lexer = new _Lexer(src);
    const tokens = [];
    let t;
    while ((t = lexer.next()).type !== TT.EOF) tokens.push(t);
    return tokens;
}


export function formatHCL(src) {
    const tokens = _tokenise(src);
    let out = '', indent = 0, needIndent = false, last = null;
    const ind = () => '  '.repeat(indent);

    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        const nx = tokens[i + 1];

        if (t.type === TT.NEWLINE) {
            // Collapse multiple blank lines to one
            if (last?.type !== TT.NEWLINE) out += '\n';
            needIndent = true;
            last = t;
            continue;
        }

        if (t.type === TT.COMMENT || t.type === TT.BLOCK_COMMENT) {
            if (needIndent) { out += ind(); needIndent = false; }
            out += t.raw;
            last = t;
            continue;
        }

        if (t.type === TT.RBRACE) {
            indent = Math.max(0, indent - 1);
            out = out.trimEnd();
            out += '\n' + ind() + '}';
            last = t;
            continue;
        }

        if (needIndent) { out += ind(); needIndent = false; }

        switch (t.type) {
            case TT.EQUALS:   out += ' = ';  break;
            case TT.COLON:    out += ': ';   break;
            case TT.ARROW:    out += ' => '; break;
            case TT.COMMA:
                out += ',';
                if (nx && nx.type !== TT.NEWLINE && nx.type !== TT.RBRACKET) out += ' ';
                break;
            case TT.LBRACE:
                out += ' {';
                indent++;
                if (!nx || nx.type === TT.NEWLINE) { out += '\n'; needIndent = true; }
                break;
            case TT.STRING:
                out += '"' + t.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')
                    .replace(/\n/g,'\\n').replace(/\t/g,'\\t') + '"';
                break;
            case TT.AND: case TT.OR: case TT.EQ: case TT.NEQ:
            case TT.LT: case TT.GT: case TT.LTE: case TT.GTE:
            case TT.PLUS: case TT.MINUS: case TT.STAR: case TT.SLASH: case TT.PERCENT:
                out += ` ${t.raw} `;
                break;
            default:
                out += t.raw;
        }
        last = t;
    }
    return out.trim();
}


const _esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

const _cls = {
    [TT.IDENTIFIER]:    'hcl-id',
    [TT.STRING]:        'hcl-str',
    [TT.NUMBER]:        'hcl-num',
    [TT.BOOLEAN]:       'hcl-kw',
    [TT.NULL]:          'hcl-kw',
    [TT.COMMENT]:       'hcl-cmt',
    [TT.BLOCK_COMMENT]: 'hcl-cmt',
    [TT.EQUALS]:        'hcl-op',
    [TT.COLON]:         'hcl-op',
    [TT.ARROW]:         'hcl-op',
    [TT.LBRACE]:        'hcl-punc',
    [TT.RBRACE]:        'hcl-punc',
    [TT.LBRACKET]:      'hcl-punc',
    [TT.RBRACKET]:      'hcl-punc',
    [TT.COMMA]:         'hcl-punc',
    [TT.TEMPLATE_START]:'hcl-tmpl',
};

export function highlightHCL(src) {
    let html = '';
    const tokens = _tokenise(src);
    for (const t of tokens) {
        if (t.type === TT.NEWLINE) { html += '\n'; continue; }
        const cls = _cls[t.type];
        const raw = t.type === TT.STRING
            ? '"' + _esc(t.value.replace(/\\/g,'\\\\').replace(/"/g,'\\"')) + '"'
            : _esc(t.raw);
        html += cls ? `<span class="${cls}">${raw}</span>` : raw;
    }
    return html;
}


export function parseHCL(src) {
    try {
        _tokenise(src); // lexer errors bubble
        // Lightweight structural check — just verify braces balance
        let depth = 0;
        for (const t of _tokenise(src)) {
            if (t.type === TT.LBRACE) depth++;
            if (t.type === TT.RBRACE) { depth--; if (depth < 0) throw new Error('Unexpected }'); }
        }
        if (depth !== 0) throw new Error('Unclosed {');
        return { success: true };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

export function validateHCL(src) {
    const r = parseHCL(src);
    return r.success ? null : r.error;
}


export const HCL_CSS = `
.hcl-id   { color: #9cdcfe; }
.hcl-str  { color: #ce9178; }
.hcl-num  { color: #b5cea8; }
.hcl-kw   { color: #569cd6; }
.hcl-cmt  { color: #6a9955; font-style: italic; }
.hcl-op   { color: #d4d4d4; }
.hcl-punc { color: #d4d4d4; }
.hcl-tmpl { color: #c586c0; }
`;