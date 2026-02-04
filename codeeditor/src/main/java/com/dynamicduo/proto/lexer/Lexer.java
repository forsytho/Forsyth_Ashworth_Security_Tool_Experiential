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
import java.util.ArrayList;
import java.util.List;
import com.dynamicduo.proto.parser.ParseException;

public class Lexer {

    private final String input;
    private final int length;
    private int pos = 0;

    private int line = 1;
    private int column = 1;

    public Lexer(String input) {
        this.input = input;
        this.length = input.length();
    }

    public List<Token> tokenize() throws ParseException {
        List<Token> tokens = new ArrayList<>();

        while (!isAtEnd()) {
            char c = peek();

            if (Character.isWhitespace(c)) {
                consumeWhitespace();
                continue;
            }

            int startLine = line;
            int startColumn = column;

            // Identifiers / keywords
            if (Character.isLetter(c)) {
                String word = readIdentifier();
                TokenType type = keywordOrIdentifier(word);
                tokens.add(new Token(type, word, startLine, startColumn));
                continue;
            }

            switch (c) {
                case '(':
                    advance();
                    tokens.add(new Token(TokenType.LPAREN, "(", startLine, startColumn));
                    break;
                case ')':
                    advance();
                    tokens.add(new Token(TokenType.RPAREN, ")", startLine, startColumn));
                    break;
                case ',':
                    advance();
                    tokens.add(new Token(TokenType.COMMA, ",", startLine, startColumn));
                    break;
                case ':':
                    advance();
                    tokens.add(new Token(TokenType.COLON, ":", startLine, startColumn));
                    break;
                case '=':
                    advance();
                    tokens.add(new Token(TokenType.EQUAL, "=", startLine, startColumn));
                    break;
                case '|':
                    advance();
                    if (match('|')) {
                        tokens.add(new Token(TokenType.CONCAT, "||", startLine, startColumn));
                    } else {
                        throw error("Expected '|' to complete '||'", startLine, startColumn);
                    }
                    break;
                case '-':
                    advance();
                    if (match('>')) {
                        tokens.add(new Token(TokenType.ARROW, "->", startLine, startColumn));
                    } else {
                        throw error("Expected '>' after '-'", startLine, startColumn);
                    }
                    break;
                default:
                    throw error("Unexpected character '" + c + "'", startLine, startColumn);
            }
        }

        tokens.add(new Token(TokenType.EOF, "", line, column));
        return tokens;
    }

    // ---------------- helpers ----------------

    private boolean isAtEnd() {
        return pos >= length;
    }

    private char peek() {
        return input.charAt(pos);
    }

    private char advance() {
        char c = input.charAt(pos++);
        if (c == '\n') {
            line++;
            column = 1;
        } else {
            column++;
        }
        return c;
    }

    private boolean match(char expected) {
        if (isAtEnd()) return false;
        if (input.charAt(pos) != expected) return false;
        advance();
        return true;
    }

    private void consumeWhitespace() {
        while (!isAtEnd() && Character.isWhitespace(peek())) {
            advance();
        }
    }

    private String readIdentifier() {
        StringBuilder sb = new StringBuilder();
        while (!isAtEnd() &&
              (Character.isLetterOrDigit(peek()) || peek() == '_')) {
            sb.append(advance());
        }
        return sb.toString();
    }

    private TokenType keywordOrIdentifier(String s) {
        return switch (s) {
            case "roles"   -> TokenType.ROLES;
            case "Enc"     -> TokenType.ENC;
            case "Dec"     -> TokenType.DEC;
            case "Mac"     -> TokenType.MAC;
            case "Sign"    -> TokenType.SIGN;
            case "Vrfy"    -> TokenType.VRFY;
            case "Hash"    -> TokenType.HASH;
            case "shared"  -> TokenType.SHARED;
            case "public"  -> TokenType.PUBLIC;
            case "private" -> TokenType.PRIVATE;
            case "key"     -> TokenType.KEY;
            case "assert"  -> TokenType.ASSERT;
            case "secret"  -> TokenType.SECRET;
            default        -> TokenType.IDENTIFIER;
        };
    }

    private ParseException error(String msg, int line, int col) {
        return new ParseException(
            "Lexer error at line " + line + ", column " + col + ": " + msg,
            null
        );
    }
}
