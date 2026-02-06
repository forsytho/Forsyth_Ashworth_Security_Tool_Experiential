/*
 *
 * Copyright (C) 2025 Owen Forsyth and Daniel Mead
 *
 * This program is free software: you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation, either version 3 of the License, or 
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

package com.dynamicduo.proto.lexer;

/**
 * Small hand written lexer.
 *
 * skip whitespace/newlines, recognize keywords, identifiers, punctuation,
 * and produce a stream of Token objects for the parser.
 */
public class Lexer {
    private final String src;
    private final int len;
    private int pos = 0;
    private int line = 1;

    public Lexer(String source) {
        this.src = source;
        this.len = source.length();
    }

    public Token nextToken() {
        skipWhitespace();

        if (isAtEnd()) {
            return new Token(TokenType.EOF, "", line);
        }

        char c = advance();

        // Single-char / multi-char symbols
        switch (c) {
            case ':':
                return new Token(TokenType.COLON, ":", line);
            case ',':
                return new Token(TokenType.COMMA, ",", line);
            case '=':
                return new Token(TokenType.EQUAL, "=", line);
            case '(':
                return new Token(TokenType.LPAREN, "(", line);
            case ')':
                return new Token(TokenType.RPAREN, ")", line);
            case '-':
                if (match('>')) {
                    return new Token(TokenType.ARROW, "->", line);
                }
                // lone '-' falls through to default handling
                break;
            case '|':
                // treat "||" as the concatenation operator.
                if (match('|')) {
                    return new Token(TokenType.CONCAT, "||", line);
                }
                // single '|' is unexpected; let it fall through so it can
                // at least surface something as an identifier-ish token.
                break;
        }

        if (Character.isLetter(c)) {
            return identifier(c);
        }

        // Unknown character: treat as IDENTIFIER lexeme so the parser
        // can surface an error instead of crashing.
        return new Token(TokenType.IDENTIFIER, String.valueOf(c), line);
    }

    // --- helpers ---

    private Token identifier(char first) {
        StringBuilder sb = new StringBuilder();
        sb.append(first);

        while (!isAtEnd() && (Character.isLetterOrDigit(peek()) || peek() == '_')) {
            sb.append(advance());
        }

        String text = sb.toString();


        // Keep original spelling for identifiers
        String raw = text;
        String lower = text.toLowerCase(); // only for keyword matching


        // Recognize keywords
        switch (lower) {
            case "roles":
                return new Token(TokenType.ROLES, raw, line);
            case "shared":  
                return new Token(TokenType.SHARED, raw, line);
            case "public":  
                return new Token(TokenType.PUBLIC, raw, line);
            case "private":
                return new Token(TokenType.PRIVATE, raw, line);
            case "key":     
                return new Token(TokenType.KEY, raw, line);
            case "assert":  
                return new Token(TokenType.ASSERT, raw, line);
            case "secret":  
                return new Token(TokenType.SECRET, raw, line);
            case "enc":
                return new Token(TokenType.ENC, raw, line);
            case "dec":
                return new Token(TokenType.DEC, raw, line);
            case "mac":
                return new Token(TokenType.MAC, raw, line);
            case "sign":
                return new Token(TokenType.SIGN, raw, line);
            case "verify":
                return new Token(TokenType.VRFY, raw, line);
            case "hash":
                return new Token(TokenType.HASH, raw, line);
            case "nonce":
                return new Token(TokenType.NONCE, raw, line);
            default:
                return new Token(TokenType.IDENTIFIER, raw, line);
        }
    }

    private void skipWhitespace() {
        while (!isAtEnd()) {
            char c = peek();
            switch (c) {
                case ' ':
                case '\r':
                case '\t':
                    advance();
                    break;
                case '\n':
                    line++;
                    advance();
                    break;
                default:
                    return;
            }
        }
    }


    private boolean isAtEnd() {
        return pos >= len;
    }

    private char peek() {
        return isAtEnd() ? '\0' : src.charAt(pos);
    }

    private char advance() {
        return src.charAt(pos++);
    }

    private boolean match(char expected) {
        if (isAtEnd())
            return false;
        if (src.charAt(pos) != expected)
            return false;
        pos++;
        return true;
    }
}
