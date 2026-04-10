/**
 * js/hcl.js
 *
 * HCL2 lexer, parser, formatter, and syntax highlighter.
 * Pure JS — no dependencies, no eval. CSP-safe.
 *
 * Implements HCL Native Syntax Specification:
 * - Structural language: attributes, blocks, bodies
 * - Expression language: literals, operations, conditionals
 * - Template language: interpolations, directives, heredocs
 * - Comments: #, //, /* *\/ with proper lexical scoping
 */

// Token types

const TT = {
    IDENTIFIER: 'IDENTIFIER',
    STRING: 'STRING',
    NUMBER: 'NUMBER',
    BOOLEAN: 'BOOLEAN',
    NULL: 'NULL',
    EQUALS: 'EQUALS',
    COLON: 'COLON',
    LBRACE: 'LBRACE',
    RBRACE: 'RBRACE',
    LBRACKET: 'LBRACKET',
    RBRACKET: 'RBRACKET',
    LPAREN: 'LPAREN',
    RPAREN: 'RPAREN',
    COMMA: 'COMMA',
    DOT: 'DOT',
    PLUS: 'PLUS',
    MINUS: 'MINUS',
    STAR: 'STAR',
    SLASH: 'SLASH',
    PERCENT: 'PERCENT',
    EQ: 'EQ',
    NEQ: 'NEQ',
    LT: 'LT',
    GT: 'GT',
    LTE: 'LTE',
    GTE: 'GTE',
    AND: 'AND',
    OR: 'OR',
    NOT: 'NOT',
    QUESTION: 'QUESTION',
    ELLIPSIS: 'ELLIPSIS',
    ARROW: 'ARROW',
    COMMENT: 'COMMENT',
    BLOCK_COMMENT: 'BLOCK_COMMENT',
    NEWLINE: 'NEWLINE',
    EOF: 'EOF',
    TEMPLATE_INTERPOLATION: 'TEMPLATE_INTERPOLATION',
    TEMPLATE_DIRECTIVE: 'TEMPLATE_DIRECTIVE',
};

class _Token {
    constructor(type, value, line, col, raw) {
        this.type = type;
        this.value = value;
        this.line = line;
        this.column = col;
        this.raw = raw ?? String(value ?? '');
    }
}

// Lexer

class _Lexer {
    constructor(src) {
        this.src = src;
        this.pos = 0;
        this.line = 1;
        this.col = 1;
    }

    next() {
        this._skipWS();
        if (this.pos >= this.src.length) {
            return new _Token(TT.EOF, null, this.line, this.col, '');
        }

        const ch = this.src[this.pos];
        const sl = this.line, sc = this.col;

        // Comments: # or // (line comments)
        if (ch === '#' || (ch === '/' && this._peek() === '/')) {
            return this._comment(sl, sc);
        }
        // Block comments: /* */
        if (ch === '/' && this._peek() === '*') {
            return this._blockComment(sl, sc);
        }

        // Heredoc: <<DELIM or <<-DELIM
        if (ch === '<' && this._peek() === '<') {
            return this._heredoc(sl, sc);
        }

        // Template interpolation or directive
        if (ch === '$' && this._peek() === '{') {
            return this._templateInterpolation(sl, sc);
        }
        if (ch === '%' && this._peek() === '{') {
            return this._templateDirective(sl, sc);
        }

        // Quoted string
        if (ch === '"') {
            return this._stringLiteral(sl, sc);
        }

        // Number literal
        if (this._isDigit(ch) || (ch === '-' && this._isDigit(this._peek()))) {
            return this._number(sl, sc);
        }

        // Identifier or keyword
        if (this._isLetter(ch) || ch === '_') {
            return this._ident(sl, sc);
        }

        // Two-character operators
        const two = ch + (this._peek() || '');
        const twoOps = new Map([
            ['==', TT.EQ],['!=', TT.NEQ], ['<=', TT.LTE], ['>=', TT.GTE],['&&', TT.AND], ['||', TT.OR], ['=>', TT.ARROW]
        ]);
        if (twoOps.has(two)) {
            this.pos += 2;
            this.col += 2;
            return new _Token(twoOps.get(two), two, sl, sc, two);
        }

        // Ellipsis ...
        if (ch === '.' && this._peek() === '.' && this._peek(2) === '.') {
            this.pos += 3;
            this.col += 3;
            return new _Token(TT.ELLIPSIS, '...', sl, sc, '...');
        }

        // Single-character tokens
        this.pos++;
        this.col++;
        const singles = new Map([
            ['=', TT.EQUALS], [':', TT.COLON],['{', TT.LBRACE], ['}', TT.RBRACE],
            ['[', TT.LBRACKET], [']', TT.RBRACKET], ['(', TT.LPAREN],[')', TT.RPAREN],
            [',', TT.COMMA], ['.', TT.DOT],['+', TT.PLUS], ['-', TT.MINUS],
            ['*', TT.STAR], ['/', TT.SLASH], ['%', TT.PERCENT], ['<', TT.LT],
            ['>', TT.GT],['!', TT.NOT], ['?', TT.QUESTION]
        ]);
        if (singles.has(ch)) {
            return new _Token(singles.get(ch), ch, sl, sc, ch);
        }

        // Newline
        if (ch === '\n') {
            this.line++;
            this.col = 1;
            return new _Token(TT.NEWLINE, '\n', sl, sc, '\n');
        }

        throw new Error(`Unexpected '${ch}' at line ${sl}:${sc}`);
    }

    _peek(n = 1) {
        return this.src[this.pos + n] ?? null;
    }

    _skipWS() {
        while (this.pos < this.src.length) {
            const c = this.src[this.pos];
            if (c === ' ' || c === '\t' || c === '\r') {
                this.pos++;
                this.col++;
            } else {
                break;
            }
        }
    }

    _comment(l, c) {
        const start = this.pos;
        if (this.src[this.pos] === '/' && this._peek() === '/') {
            this.pos += 2;
            this.col += 2;
        } else {
            this.pos++;
            this.col++;
        }
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') {
            this.pos++;
            this.col++;
        }
        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.COMMENT, raw, l, c, raw);
    }

    _blockComment(l, c) {
        const start = this.pos;
        this.pos += 2;
        this.col += 2;
        while (this.pos < this.src.length - 1) {
            if (this.src[this.pos] === '*' && this.src[this.pos + 1] === '/') {
                this.pos += 2;
                this.col += 2;
                break;
            }
            if (this.src[this.pos] === '\n') {
                this.line++;
                this.col = 1;
            } else {
                this.col++;
            }
            this.pos++;
        }
        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.BLOCK_COMMENT, raw, l, c, raw);
    }

    _heredoc(l, c) {
        const start = this.pos;
        this.pos += 2;
        this.col += 2;

        let indentStrip = false;
        if (this.src[this.pos] === '-') {
            indentStrip = true;
            this.pos++;
            this.col++;
        }

        const delimStart = this.pos;
        while (this.pos < this.src.length && this.src[this.pos] !== '\n') {
            this.pos++;
            this.col++;
        }
        const delimiter = this.src.slice(delimStart, this.pos).trim();

        if (this.pos < this.src.length && this.src[this.pos] === '\n') {
            this.pos++;
            this.line++;
            this.col = 1;
        }

        const lines =[];
        while (this.pos < this.src.length) {
            const lineStart = this.pos;
            while (this.pos < this.src.length && this.src[this.pos] !== '\n') {
                this.pos++;
            }
            const lineContent = this.src.slice(lineStart, this.pos);
            const isMatch = indentStrip ? lineContent.trim() === delimiter : lineContent.trimEnd() === delimiter;

            if (isMatch) {
                if (this.pos < this.src.length && this.src[this.pos] === '\n') {
                    this.pos++;
                    this.line++;
                    this.col = 1;
                }
                break;
            }
            lines.push(lineContent);
            if (this.pos < this.src.length && this.src[this.pos] === '\n') {
                this.pos++;
                this.line++;
                this.col = 1;
            }
        }

        let content = lines.join('\n');
        if (indentStrip && lines.length > 0) {
            const nonEmpty = lines.filter(ln => ln.trim());
            if (nonEmpty.length > 0) {
                const minIndent = Math.min(...nonEmpty.map(ln => {
                    const match = ln.match(/^(\s*)/);
                    return match ? match[1].length : 0;
                }));
                content = lines.map(ln => ln.slice(minIndent)).join('\n');
            }
        }

        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.STRING, content, l, c, raw);
    }

    _templateInterpolation(l, c) {
        const start = this.pos;
        this.pos += 2; // consume ${
        this.col += 2;

        let depth = 1;
        let content = '';
        let inStr = false;
        let esc = false;

        while (this.pos < this.src.length && depth > 0) {
            const ch = this.src[this.pos];
            if (inStr) {
                if (esc) esc = false;
                else if (ch === '\\') esc = true;
                else if (ch === '"') inStr = false;

                content += ch;
                this.pos++;
                this.col++;
            } else {
                if (ch === '"') inStr = true;
                else if (ch === '{') depth++;
                else if (ch === '}') depth--;

                if (depth > 0 || ch !== '}') {
                    content += ch;
                }
                this.pos++;
                this.col++;
            }
        }

        if (depth !== 0) {
            throw new Error(`Unterminated template interpolation at line ${l}:${c}`);
        }

        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.TEMPLATE_INTERPOLATION, content, l, c, raw);
    }

    _templateDirective(l, c) {
        const start = this.pos;
        this.pos += 2; // consume %{
        this.col += 2;

        let depth = 1;
        let content = '';
        let inStr = false;
        let esc = false;

        while (this.pos < this.src.length && depth > 0) {
            const ch = this.src[this.pos];
            if (inStr) {
                if (esc) esc = false;
                else if (ch === '\\') esc = true;
                else if (ch === '"') inStr = false;

                content += ch;
                this.pos++;
                this.col++;
            } else {
                if (ch === '"') inStr = true;
                else if (ch === '{') depth++;
                else if (ch === '}') depth--;

                if (depth > 0 || ch !== '}') {
                    content += ch;
                }
                this.pos++;
                this.col++;
            }
        }

        if (depth !== 0) {
            throw new Error(`Unterminated template directive at line ${l}:${c}`);
        }

        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.TEMPLATE_DIRECTIVE, content, l, c, raw);
    }

    _stringLiteral(l, c) {
        const start = this.pos;
        this.pos++; // consume opening "
        this.col++;

        let result = '';
        let escaped = false;
        let templateDepth = 0;
        let inTmplString = false;
        let tmplStringEscaped = false;

        while (this.pos < this.src.length) {
            const ch = this.src[this.pos];

            if (templateDepth === 0) {
                if (!escaped && ch === '$' && this._peek() === '{') {
                    templateDepth++;
                    result += '${';
                    this.pos += 2;
                    this.col += 2;
                    continue;
                }
                if (!escaped && ch === '%' && this._peek() === '{') {
                    templateDepth++;
                    result += '%{';
                    this.pos += 2;
                    this.col += 2;
                    continue;
                }
                if (!escaped && ch === '\\') {
                    escaped = true;
                    this.pos++;
                    this.col++;
                    continue;
                }
                if (!escaped && ch === '"') {
                    this.pos++;
                    this.col++;
                    const raw = this.src.slice(start, this.pos);
                    return new _Token(TT.STRING, result, l, c, raw);
                }
                if (escaped) {
                    if (ch === 'u' || ch === 'U') {
                        const isUpper = ch === 'U';
                        const hexLen = isUpper ? 8 : 4;
                        let hex = '';
                        this.pos++;
                        this.col++;
                        for (let i = 0; i < hexLen && this.pos < this.src.length; i++) {
                            const hc = this.src[this.pos];
                            if (this._isHexDigit(hc)) {
                                hex += hc;
                                this.pos++;
                                this.col++;
                            } else {
                                break;
                            }
                        }
                        if (hex.length === hexLen) {
                            result += String.fromCodePoint(parseInt(hex, 16));
                        } else {
                            result += '\\' + (isUpper ? 'U' : 'u') + hex;
                        }
                    } else {
                        const esc = { 'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\' };
                        result += esc[ch] ?? ch;
                        this.pos++;
                        this.col++;
                    }
                    escaped = false;
                } else {
                    result += ch;
                    this.pos++;
                    this.col++;
                }
            } else {
                // Inside template interpolation
                if (inTmplString) {
                    if (tmplStringEscaped) {
                        tmplStringEscaped = false;
                    } else if (ch === '\\') {
                        tmplStringEscaped = true;
                    } else if (ch === '"') {
                        inTmplString = false;
                    }
                    result += ch;
                    this.pos++;
                    this.col++;
                } else {
                    if (ch === '"') {
                        inTmplString = true;
                    } else if (ch === '{') {
                        templateDepth++;
                    } else if (ch === '}') {
                        templateDepth--;
                    }
                    result += ch;
                    this.pos++;
                    this.col++;
                }
            }
        }
        throw new Error(`Unterminated string at line ${l}:${c}`);
    }

    _isHexDigit(ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    _number(l, c) {
        const start = this.pos;

        // Handle base prefixes: 0x, 0o, 0b
        if (this.src[this.pos] === '0') {
            const next = this.src[this.pos + 1];
            if (next === 'x' || next === 'X') return this._parseBase(l, c, 16, 2);
            if (next === 'o' || next === 'O') return this._parseBase(l, c, 8, 2);
            if (next === 'b' || next === 'B') return this._parseBase(l, c, 2, 2);
        }

        // Optional leading minus
        if (this.src[this.pos] === '-') {
            this.pos++;
            this.col++;
        }

        // Integer part
        while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) {
            this.pos++;
            this.col++;
        }

        // Fractional part
        if (this.src[this.pos] === '.' && this._isDigit(this._peek())) {
            this.pos++;
            this.col++;
            while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) {
                this.pos++;
                this.col++;
            }
        }

        // Exponent
        if (this.pos < this.src.length && 'eE'.includes(this.src[this.pos])) {
            this.pos++;
            this.col++;
            if ('+-'.includes(this.src[this.pos])) {
                this.pos++;
                this.col++;
            }
            while (this.pos < this.src.length && this._isDigit(this.src[this.pos])) {
                this.pos++;
                this.col++;
            }
        }

        const raw = this.src.slice(start, this.pos);
        return new _Token(TT.NUMBER, parseFloat(raw), l, c, raw);
    }

    _parseBase(l, c, base, prefixLen) {
        const start = this.pos;
        this.pos += prefixLen;
        this.col += prefixLen;

        while (this.pos < this.src.length) {
            const ch = this.src[this.pos];
            let valid = false;
            if (base === 16) valid = this._isHexDigit(ch);
            else if (base === 8) valid = ch >= '0' && ch <= '7';
            else if (base === 2) valid = ch === '0' || ch === '1';
            if (valid) {
                this.pos++;
                this.col++;
            } else {
                break;
            }
        }

        const raw = this.src.slice(start, this.pos);
        const digits = raw.slice(prefixLen);
        const value = parseInt(digits || '0', base);
        return new _Token(TT.NUMBER, value, l, c, raw);
    }

    _ident(l, c) {
        const start = this.pos;
        while (this.pos < this.src.length) {
            const ch = this.src[this.pos];
            if (this._isLetter(ch) || this._isDigit(ch) || ch === '_' || ch === '-') {
                this.pos++;
                this.col++;
            } else {
                break;
            }
        }
        const raw = this.src.slice(start, this.pos);

        if (raw === 'true' || raw === 'false') {
            return new _Token(TT.BOOLEAN, raw === 'true', l, c, raw);
        }
        if (raw === 'null') {
            return new _Token(TT.NULL, null, l, c, raw);
        }
        return new _Token(TT.IDENTIFIER, raw, l, c, raw);
    }

    _isDigit(ch) { return ch >= '0' && ch <= '9'; }
    _isLetter(ch) { return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'); }
}

// Token caching

const _tokenCache = new Map();

function _tokenise(src) {
    if (_tokenCache.has(src)) return _tokenCache.get(src);

    const lexer = new _Lexer(src);
    const tokens =[];
    let t;
    while ((t = lexer.next()).type !== TT.EOF) {
        tokens.push(t);
    }

    if (src.length < 100000) {
        _tokenCache.set(src, tokens);
    }
    return tokens;
}

// Parser

class _Parser {
    constructor(tokens) {
        this.tokens = tokens;
        this.pos = 0;
        this.data = {};
    }

    peek() { return this.tokens[this.pos] || new _Token(TT.EOF, null, 0, 0, ''); }

    advance() {
        const t = this.tokens[this.pos];
        if (this.pos < this.tokens.length) this.pos++;
        return t || new _Token(TT.EOF, null, 0, 0, '');
    }

    match(type) {
        if (this.peek().type === type) return this.advance();
        return null;
    }

    expect(type, msg) {
        const t = this.peek();
        if (t.type !== type) {
            throw new Error(`${msg} at line ${t.line}:${t.column}, found ${t.type}`);
        }
        return this.advance();
    }

    parse() {
        while (this.peek().type !== TT.EOF) {
            this._skipNewlinesAndComments();
            if (this.peek().type === TT.EOF) break;
            this._parseTopLevel();
        }
        return this.data;
    }

    _skipNewlinesAndComments() {
        while (true) {
            const t = this.peek();
            if (t.type === TT.NEWLINE || t.type === TT.COMMENT || t.type === TT.BLOCK_COMMENT) {
                this.advance();
            } else {
                break;
            }
        }
    }

    _parseTopLevel() {
        this._skipNewlinesAndComments();
        const t = this.peek();
        if (t.type === TT.EOF) return;

        if (t.type === TT.IDENTIFIER) {
            const ident = this.advance();
            this._skipNewlinesAndComments();

            if (this.peek().type === TT.EQUALS) {
                this.advance();
                this.data[ident.value] = this._parseValue();
                return;
            }

            // Block with labels
            const labels =[];
            while (this.peek().type === TT.IDENTIFIER || this.peek().type === TT.STRING) {
                labels.push(this.advance().value);
                this._skipNewlinesAndComments();
            }

            if (this.peek().type === TT.LBRACE) {
                this.advance();
                const blockData = this._parseBlockBody();
                this.expect(TT.RBRACE, 'Expected closing brace for block');

                if (!this.data[ident.value]) this.data[ident.value] =[];
                if (labels.length > 0) blockData.labels = labels;
                this.data[ident.value].push(blockData);
            } else {
                throw new Error(`Expected '=' or '{' after ${ident.value} at line ${ident.line}:${ident.column}`);
            }
        } else {
            this.advance();
        }
    }

    _parseBlockBody() {
        const result = {};
        while (true) {
            this._skipNewlinesAndComments();
            const t = this.peek();
            if (t.type === TT.RBRACE || t.type === TT.EOF) break;

            if (t.type === TT.IDENTIFIER) {
                const ident = this.advance();
                this._skipNewlinesAndComments();

                if (this.peek().type === TT.EQUALS) {
                    this.advance();
                    result[ident.value] = this._parseValue();
                    continue;
                }

                const labels =[];
                while (this.peek().type === TT.IDENTIFIER || this.peek().type === TT.STRING) {
                    labels.push(this.advance().value);
                    this._skipNewlinesAndComments();
                }

                if (this.peek().type === TT.LBRACE) {
                    this.advance();
                    const blockData = this._parseBlockBody();
                    this.expect(TT.RBRACE, 'Expected closing brace for nested block');

                    if (!result[ident.value]) result[ident.value] =[];
                    if (labels.length > 0) blockData.labels = labels;
                    result[ident.value].push(blockData);
                } else {
                    throw new Error(`Expected '=' or '{' in block body at line ${ident.line}:${ident.column}`);
                }
            } else {
                this.advance();
            }
        }
        return result;
    }

    _parseValue() {
        this._skipNewlinesAndComments();
        const t = this.peek();

        switch (t.type) {
            case TT.STRING:
                return this.advance().value;
            case TT.NUMBER:
                return this.advance().value;
            case TT.BOOLEAN:
                return this.advance().value;
            case TT.NULL:
                this.advance();
                return null;
            case TT.LBRACKET:
                return this._parseList();
            case TT.LBRACE:
                return this._parseObject();
            case TT.TEMPLATE_INTERPOLATION:
                this.advance();
                return { _expr: true, template: t.value };
            default:
                return this._skipExpressionValue();
        }
    }

    _parseList() {
        this.advance();
        const items =[];
        while (true) {
            this._skipNewlinesAndComments();
            const t = this.peek();
            if (t.type === TT.RBRACKET || t.type === TT.EOF) break;
            items.push(this._parseValue());
            this._skipNewlinesAndComments();
            if (this.peek().type === TT.COMMA) {
                this.advance();
            } else if (this.peek().type !== TT.RBRACKET && this.peek().type !== TT.EOF) {
                break;
            }
        }
        this.expect(TT.RBRACKET, 'Expected closing bracket');
        return items;
    }

    _parseObject() {
        this.advance();
        const obj = {};
        while (true) {
            this._skipNewlinesAndComments();
            const t = this.peek();
            if (t.type === TT.RBRACE || t.type === TT.EOF) break;

            let key;
            if (t.type === TT.IDENTIFIER || t.type === TT.STRING) {
                key = this.advance().value;
            } else {
                this.advance();
                continue;
            }

            this._skipNewlinesAndComments();
            if (this.peek().type === TT.EQUALS) {
                this.advance();
                obj[key] = this._parseValue();
            } else {
                this.advance();
            }
            this._skipNewlinesAndComments();
            if (this.peek().type === TT.COMMA) this.advance();
        }
        this.expect(TT.RBRACE, 'Expected closing brace');
        return obj;
    }

    _skipExpressionValue() {
        let depth = 0;
        while (true) {
            const t = this.peek();
            if (t.type === TT.EOF) break;
            if ((t.type === TT.NEWLINE || t.type === TT.COMMA) && depth === 0) break;
            if ((t.type === TT.RBRACE || t.type === TT.RBRACKET) && depth === 0) break;
            if ([TT.LPAREN, TT.LBRACE, TT.LBRACKET, TT.TEMPLATE_INTERPOLATION, TT.TEMPLATE_DIRECTIVE].includes(t.type)) depth++;
            if ([TT.RPAREN, TT.RBRACE, TT.RBRACKET].includes(t.type)) depth--;
            this.advance();
        }
        return { _expr: true };
    }
}

// Formatter

export function formatHCL(src) {
    if (!src || src.trim() === '') return '';

    const tokens = _tokenise(src);
    let out = '';
    let indent = 0;
    let needIndent = true;
    let lastWasNewline = false;
    let lastTokenType = null;
    let inBlock = false;
    let pendingNewline = false;
    const ind = () => '  '.repeat(indent);

    // Validate brace balance with line numbers
    const stack = [];
    const pairs = { [TT.LBRACE]: TT.RBRACE,[TT.LBRACKET]: TT.RBRACKET, [TT.LPAREN]: TT.RPAREN };
    for (const t of tokens) {
        if (pairs[t.type]) {
            stack.push({ type: t.type, line: t.line, col: t.column });
        } else if (Object.values(pairs).includes(t.type)) {
            const last = stack.pop();
            if (!last || pairs[last.type] !== t.type) {
                throw new Error(`Mismatched braces at line ${t.line}:${t.column}`);
            }
        }
    }
    if (stack.length > 0) {
        const unclosed = stack[0];
        throw new Error(`Unclosed ${unclosed.type} at line ${unclosed.line}:${unclosed.col}`);
    }

    for (let i = 0; i < tokens.length; i++) {
        const t = tokens[i];
        const next = tokens[i + 1];
        const prev = tokens[i - 1];

        // Newline handling
        if (t.type === TT.NEWLINE) {
            if (!lastWasNewline && out.length > 0) {
                out += '\n';
                pendingNewline = false;
            }
            needIndent = true;
            lastWasNewline = true;
            lastTokenType = t.type;
            inBlock = false;
            continue;
        }

        // Comment handling
        if (t.type === TT.COMMENT || t.type === TT.BLOCK_COMMENT) {
            if (needIndent) {
                out += ind();
                needIndent = false;
            }
            if (lastTokenType && ![TT.NEWLINE, TT.COMMENT, TT.BLOCK_COMMENT].includes(lastTokenType)) {
                out = out.trimEnd() + '\n' + ind();
            }
            out += t.raw;
            lastWasNewline = false;
            lastTokenType = t.type;
            continue;
        }

        // Closing brace: dedent first, then output on new line
        if (t.type === TT.RBRACE) {
            indent = Math.max(0, indent - 1);
            out = out.trimEnd();
            out += '\n' + ind() + '}';
            needIndent = false;
            lastWasNewline = true;
            lastTokenType = t.type;
            inBlock = false;
            continue;
        }

        // Apply indentation at line start
        if (needIndent) {
            out += ind();
            needIndent = false;
            lastWasNewline = false;
        }

        // Handle opening brace and ensure each attribute is on its own line
        if (t.type === TT.LBRACE) {
            // Remove trailing space before {
            out = out.trimEnd();

            if (next?.type === TT.RBRACE) {
                out += ' {}';
                i++;
            } else {
                out += ' {';
                indent++;
                // Add newline after opening brace for better formatting
                out += '\n';
                needIndent = true;
                lastWasNewline = true;
                inBlock = true;
            }
            lastTokenType = t.type;
            continue;
        }

        // Ensure attributes within blocks are on separate lines
        if (inBlock && lastTokenType === TT.NEWLINE && t.type === TT.IDENTIFIER && next?.type === TT.EQUALS) {
            // Already have newline, good
        } else if (inBlock && lastTokenType !== TT.NEWLINE && lastTokenType !== TT.LBRACE &&
            (t.type === TT.IDENTIFIER || t.type === TT.STRING) && next?.type === TT.EQUALS) {
            // Need to add newline before attribute
            if (!out.endsWith('\n')) {
                out += '\n' + ind();
                needIndent = false;
            }
        }

        // Token-specific formatting
        switch (t.type) {
            case TT.EQUALS:
            case TT.COLON:
            case TT.ARROW:
                out += ` ${t.raw} `;
                break;

            case TT.COMMA:
                out += ', ';
                break;

            case TT.LBRACKET:
                out += '[';
                break;

            case TT.RBRACKET:
                out += ']';
                break;

            case TT.STRING: {
                let res = '"';
                let idx = 0;
                while (idx < t.value.length) {
                    if ((t.value[idx] === '$' || t.value[idx] === '%') && t.value[idx+1] === '{') {
                        res += t.value[idx] + '{';
                        idx += 2;
                        let tmplDepth = 1;
                        let inStr = false;
                        let esc = false;
                        while (idx < t.value.length && tmplDepth > 0) {
                            let ch = t.value[idx];
                            if (inStr) {
                                if (esc) esc = false;
                                else if (ch === '\\') esc = true;
                                else if (ch === '"') inStr = false;
                            } else {
                                if (ch === '"') inStr = true;
                                else if (ch === '{') tmplDepth++;
                                else if (ch === '}') tmplDepth--;
                            }
                            res += ch;
                            idx++;
                        }
                    } else {
                        let ch = t.value[idx];
                        if (ch === '\n') res += '\\n';
                        else if (ch === '\r') res += '\\r';
                        else if (ch === '\t') res += '\\t';
                        else if (ch === '\\') res += '\\\\';
                        else if (ch === '"') res += '\\"';
                        else res += ch;
                        idx++;
                    }
                }
                res += '"';
                out += res;
                // Space after string only for block labels or specific tokens
                if (next &&[TT.IDENTIFIER, TT.STRING].includes(next.type)) {
                    out += ' ';
                } else if (next && ![TT.COMMA, TT.RBRACKET, TT.RBRACE, TT.NEWLINE, TT.EOF, TT.EQUALS].includes(next.type)) {
                    out += ' ';
                }
                break;
            }

            case TT.IDENTIFIER:
                out += t.raw;
                // Space after identifier for block labels or before non-punctuation
                if (next && [TT.IDENTIFIER, TT.STRING].includes(next.type)) {
                    out += ' ';
                } else if (next && ![TT.COMMA, TT.RBRACKET, TT.RBRACE, TT.NEWLINE, TT.EOF, TT.EQUALS, TT.LBRACE, TT.DOT].includes(next.type)) {
                    out += ' ';
                }
                break;

            case TT.DOT:
                out += '.';
                break;

            // Binary operators: single space padding (no double spaces)
            case TT.PLUS:
            case TT.MINUS:
            case TT.STAR:
            case TT.SLASH:
            case TT.PERCENT:
            case TT.EQ:
            case TT.NEQ:
            case TT.LT:
            case TT.GT:
            case TT.LTE:
            case TT.GTE:
            case TT.AND:
            case TT.OR:
                // Ensure single space before operator if needed
                if (prev && !lastWasNewline && out.length > 0 && out[out.length - 1] !== ' ') {
                    out += ' ';
                }
                out += t.raw;
                // Ensure single space after operator if needed
                if (next && ![TT.COMMA, TT.RBRACKET, TT.RBRACE, TT.RPAREN, TT.NEWLINE, TT.EOF].includes(next.type)) {
                    out += ' ';
                }
                break;

            case TT.NOT:
                out += t.raw;
                if (next && ![TT.RPAREN, TT.RBRACKET, TT.RBRACE, TT.COMMA, TT.NEWLINE, TT.EOF].includes(next.type)) {
                    out += ' ';
                }
                break;

            case TT.TEMPLATE_INTERPOLATION:
            case TT.TEMPLATE_DIRECTIVE:
                out += t.raw;
                break;

            default:
                out += t.raw;
                if (next && ![TT.COMMA, TT.RBRACKET, TT.RBRACE, TT.RPAREN, TT.NEWLINE, TT.EOF, TT.DOT].includes(next.type)) {
                    out += ' ';
                }
        }

        lastTokenType = t.type;
        if (lastWasNewline && ![TT.NEWLINE, TT.COMMENT, TT.BLOCK_COMMENT].includes(t.type)) {
            lastWasNewline = false;
        }
    }

    // Clean up multiple newlines
    return out.replace(/\n\s*\n\s*\n/g, '\n\n').trim();
}

function _isOperator(type) {
    return new Set([
        TT.PLUS, TT.MINUS, TT.STAR, TT.SLASH, TT.PERCENT,
        TT.EQ, TT.NEQ, TT.LT, TT.GT, TT.LTE, TT.GTE,
        TT.AND, TT.OR, TT.NOT
    ]).has(type);
}

// Syntax Highlighter

const _escHtml = s => String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

const _clsMap = new Map([[TT.IDENTIFIER, 'hcl-id'], [TT.STRING, 'hcl-str'],[TT.NUMBER, 'hcl-num'],
    [TT.BOOLEAN, 'hcl-kw'],[TT.NULL, 'hcl-kw'],
    [TT.COMMENT, 'hcl-cmt'],[TT.BLOCK_COMMENT, 'hcl-cmt'],[TT.EQUALS, 'hcl-op'], [TT.COLON, 'hcl-op'],[TT.ARROW, 'hcl-op'],
    [TT.EQ, 'hcl-op'],[TT.NEQ, 'hcl-op'], [TT.LT, 'hcl-op'], [TT.GT, 'hcl-op'],
    [TT.LTE, 'hcl-op'],[TT.GTE, 'hcl-op'], [TT.AND, 'hcl-op'], [TT.OR, 'hcl-op'],
    [TT.NOT, 'hcl-op'], [TT.PLUS, 'hcl-op'],[TT.MINUS, 'hcl-op'],
    [TT.STAR, 'hcl-op'], [TT.SLASH, 'hcl-op'], [TT.PERCENT, 'hcl-op'],
    [TT.LBRACE, 'hcl-punc'],[TT.RBRACE, 'hcl-punc'],
    [TT.LBRACKET, 'hcl-punc'],[TT.RBRACKET, 'hcl-punc'],[TT.LPAREN, 'hcl-punc'], [TT.RPAREN, 'hcl-punc'],[TT.COMMA, 'hcl-punc'], [TT.DOT, 'hcl-punc'],[TT.TEMPLATE_INTERPOLATION, 'hcl-tmpl'],[TT.TEMPLATE_DIRECTIVE, 'hcl-tmpl']
]);

export function highlightHCL(src, options = {}) {
    const { lineNumbers = false, startLine = 1, wrapperClass = 'hcl-code' } = options;
    if (!src || src.trim() === '') return '';

    let html = '', currentLine = startLine, lineHtml = '';
    const tokens = _tokenise(src);

    if (lineNumbers) {
        html += `<div class="${wrapperClass}"><div class="hcl-line-numbers">`;
    } else {
        html += `<div class="${wrapperClass}">`;
    }

    for (const t of tokens) {
        if (t.type === TT.NEWLINE) {
            if (lineNumbers) {
                html += `<div class="hcl-line"><span class="hcl-line-number">${currentLine}</span><span class="hcl-line-content">${lineHtml}</span></div>`;
                lineHtml = '';
                currentLine++;
            } else {
                html += '\n';
            }
            continue;
        }

        const cls = _clsMap.get(t.type);
        let raw;

        if (t.type === TT.STRING) {
            let res = '';
            let idx = 0;
            while (idx < t.value.length) {
                if ((t.value[idx] === '$' || t.value[idx] === '%') && t.value[idx+1] === '{') {
                    res += '</span><span class="hcl-tmpl">' + t.value[idx] + '{';
                    idx += 2;
                    let tmplDepth = 1;
                    let inStr = false;
                    let esc = false;
                    while (idx < t.value.length && tmplDepth > 0) {
                        let ch = t.value[idx];
                        if (inStr) {
                            if (esc) esc = false;
                            else if (ch === '\\') esc = true;
                            else if (ch === '"') inStr = false;
                        } else {
                            if (ch === '"') inStr = true;
                            else if (ch === '{') tmplDepth++;
                            else if (ch === '}') tmplDepth--;
                        }
                        res += _escHtml(ch);
                        idx++;
                    }
                    res += '</span><span class="hcl-str">';
                } else {
                    let ch = t.value[idx];
                    if (ch === '\n') res += '\\n';
                    else if (ch === '\r') res += '\\r';
                    else if (ch === '\t') res += '\\t';
                    else if (ch === '\\') res += '\\\\';
                    else if (ch === '"') res += '\\"';
                    else res += _escHtml(ch);
                    idx++;
                }
            }
            raw = '"' + res + '"';
        } else if (t.type === TT.TEMPLATE_INTERPOLATION || t.type === TT.TEMPLATE_DIRECTIVE) {
            raw = _escHtml(t.raw);
        } else {
            raw = _escHtml(t.raw);
        }

        const span = cls ? `<span class="${cls}">${raw}</span>` : raw;

        if (lineNumbers) {
            lineHtml += span;
        } else {
            html += span;
        }
    }

    if (lineNumbers) {
        if (lineHtml) {
            html += `<div class="hcl-line"><span class="hcl-line-number">${currentLine}</span><span class="hcl-line-content">${lineHtml}</span></div>`;
        }
        html += '</div></div>';
    } else {
        if (lineHtml) html += lineHtml;
        html += '</div>';
    }
    return html;
}

// Validation API

export function parseHCL(src) {
    try {
        const tokens = _tokenise(src);

        // Brace validation
        const stack = [];
        const pairs = { [TT.LBRACE]: TT.RBRACE, [TT.LBRACKET]: TT.RBRACKET, [TT.LPAREN]: TT.RPAREN };
        for (const t of tokens) {
            if (pairs[t.type]) {
                stack.push({ type: t.type, line: t.line, col: t.column });
            } else if (Object.values(pairs).includes(t.type)) {
                const last = stack.pop();
                if (!last || pairs[last.type] !== t.type) {
                    throw new Error(`Unexpected ${t.raw} at line ${t.line}:${t.column}`);
                }
            }
        }
        if (stack.length > 0) {
            const unclosed = stack[0];
            throw new Error(`Unclosed ${unclosed.type} at line ${unclosed.line}:${unclosed.col}`);
        }

        const parser = new _Parser(tokens);
        return { success: true, data: parser.parse() };
    } catch (e) {
        return { success: false, error: e.message };
    }
}

export function validateHCL(src) {
    const result = parseHCL(src);
    return result.success ? null : result.error;
}

// CSS Styles

let _cssInjected = false;

export const HCL_CSS = `
.hcl-code {
    font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
    font-size: 14px; line-height: 1.5;
    background: #1e1e1e; color: #d4d4d4;
    border-radius: 6px; overflow-x: auto;
}
.hcl-line { display: flex; min-height: 1.5em; }
.hcl-line-number {
    user-select: none; text-align: right;
    padding: 0 12px 0 8px; color: #858585;
    background: #252525; border-right: 1px solid #404040;
    min-width: 3em;
}
.hcl-line-content { flex: 1; padding-left: 8px; white-space: pre; }
.hcl-id   { color: #9cdcfe; }
.hcl-str  { color: #ce9178; }
.hcl-num  { color: #b5cea8; }
.hcl-kw   { color: #569cd6; font-weight: 500; }
.hcl-cmt  { color: #6a9955; font-style: italic; }
.hcl-op   { color: #d4d4d4; font-weight: 500; }
.hcl-punc { color: #d4d4d4; }
.hcl-tmpl { color: #9cdcfe; background: rgba(255,255,255,0.05); border-radius: 3px; padding: 0 2px; }
@media (prefers-color-scheme: light) {
    .hcl-code { background: #f5f5f5; color: #333; }
    .hcl-line-number { background: #e8e8e8; color: #666; border-right-color: #ccc; }
    .hcl-id { color: #0070c0; } .hcl-str { color: #a31515; }
    .hcl-num { color: #098658; } .hcl-kw { color: #0000ff; }
    .hcl-cmt { color: #008000; } .hcl-op, .hcl-punc { color: #000; }
    .hcl-tmpl { background: rgba(0,0,0,0.05); }
}
`;


export function injectHCSS() {
    if (typeof document === 'undefined') return;

    try {
        const exists = Array.from(document.styleSheets || []).some(sheet => {
            try {
                return Array.from(sheet.cssRules || []).some(rule =>
                    rule.cssText?.includes('.hcl-id')
                );
            } catch { return false; }
        });
        if (exists) return;
    } catch {
        if (_cssInjected) return;
    }

    const style = document.createElement('style');
    style.textContent = HCL_CSS;
    document.head.appendChild(style);
    _cssInjected = true;
}

if (typeof window !== 'undefined' && window.document) {
    injectHCSS();
}
