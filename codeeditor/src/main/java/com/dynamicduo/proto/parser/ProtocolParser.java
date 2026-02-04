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
 * I should have received a copy of the GNU General Public License 
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

package com.dynamicduo.proto.parser;

import com.dynamicduo.proto.lexer.*;
import com.dynamicduo.proto.ast.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Recursive-descent parser for the protocol language.
 *
 * Right now this support:
 *
 *   protocol  → rolesDecl message* EOF ;
 *   rolesDecl → "roles" ":" IDENT ( "," IDENT )* ;
 *   message   → IDENT ARROW IDENT ":" stmt ;
 *   stmt      → IDENT "=" expr | expr ;
 *
 *   expr         → concatExpr ;
 *   concatExpr   → cryptoExpr ( "||" cryptoExpr )* ;
 *   cryptoExpr   → encExpr
 *                | macExpr
 *                | signExpr
 *                | verifyExpr
 *                | hashExpr
 *                | IDENT ;
 *
 *   encExpr      → "Enc"    "(" expr "," expr ")" ;
 *   macExpr      → "Mac"    "(" IDENT "," expr ")" ;
 *   signExpr     → "Sign"   "(" IDENT "," expr ")" ;
 *   verifyExpr   → "Verify" "(" IDENT "," expr "," expr ")" ;
 *   hashExpr     → "Hash"      "(" expr ")" ;
 *
 * I can extend this later with key/init/assert sections without changing
 * the basic expression structure.
 */
public class ProtocolParser {

    private final List<Token> tokens;
    private int current = 0;

    /**
     * Updated constructor: pulls all tokens using lexer.tokenize()
     */
    public ProtocolParser(Lexer lexer) throws ParseException {
        this.tokens = lexer.tokenize(); // <-- matches your new Lexer
    }

    /** Entry point: parse a ProtocolNode or throw ParseException on error. */
    public ProtocolNode parse() throws ParseException {
        // 1) roles: Alice, Bob, Server
        RoleDeclNode roles = rolesDecl();
        ProtocolNode proto = new ProtocolNode(roles);

        // 2) zero or more key declarations
        while (check(TokenType.SHARED) || check(TokenType.PUBLIC) || check(TokenType.PRIVATE)) {
            if (match(TokenType.SHARED)) {
                proto.addKeyDecl(sharedKeyDecl());
            } else if (match(TokenType.PUBLIC)) {
                proto.addKeyDecl(publicKeyDecl());
            } else if (match(TokenType.PRIVATE)) {
                proto.addKeyDecl(privateKeyDecl());
            }
        }

        // 3) messages
       while (check(TokenType.IDENTIFIER)) {
            MessageSendNode msg = message();
            proto.addMessage(msg);
        }


        // 4) consume EOF explicitly (cleaner errors if trailing garbage exists)
        consume(TokenType.EOF, "Expected end of input.");
        return proto;
    }

    // --------------------------------------------------------------------
    // Top-level pieces
    // --------------------------------------------------------------------

    // rolesDecl → "roles" ":" IDENT ( "," IDENT )* ;
    private RoleDeclNode rolesDecl() throws ParseException {
        consume(TokenType.ROLES, "Expected 'roles' declaration (example: roles: Alice, Bob).");
        consume(TokenType.COLON, "Expected ':' after 'roles' (example: roles: Alice, Bob).");

        RoleDeclNode roles = new RoleDeclNode();
        roles.addRole(identifier("Expected role name after 'roles:'."));

        while (match(TokenType.COMMA)) {
            roles.addRole(identifier("Expected role name after ','."));
        }
        return roles;
    }

    // message → IDENT ARROW IDENT ":" stmt ;
    private MessageSendNode message() throws ParseException {
        IdentifierNode sender = identifier("Expected sender identifier at start of message.");
        consume(TokenType.ARROW, "Expected '->' after sender (example: Alice -> Bob: ...).");
        IdentifierNode receiver = identifier("Expected receiver identifier after '->'.");
        consume(TokenType.COLON, "Expected ':' after receiver (example: Alice -> Bob: stmt).");
        SyntaxNode body = stmt();
        return new MessageSendNode(sender, receiver, body);
    }

    // --------------------------------------------------------------------
    // Statements and expressions
    // --------------------------------------------------------------------

    // stmt → IDENT "=" expr | expr ;
    private SyntaxNode stmt() throws ParseException {
        if (check(TokenType.IDENTIFIER) && checkNext(TokenType.EQUAL)) {
            IdentifierNode target = identifier("Expected variable name before '='.");
            consume(TokenType.EQUAL, "Expected '=' after variable.");
            SyntaxNode value = expr();
            return new AssignNode(target, value);
        }
        return expr();
    }

    // expr → concatExpr ;
    private SyntaxNode expr() throws ParseException {
        return concatExpr();
    }

    // concatExpr → cryptoExpr ( "||" cryptoExpr )* ;
    private SyntaxNode concatExpr() throws ParseException {
        SyntaxNode left = cryptoExpr();
        while (match(TokenType.CONCAT)) {
            SyntaxNode right = cryptoExpr();
            left = new ConcatNode(left, right);
        }
        return left;
    }

    // cryptoExpr → ENC | MAC | SIGN | VRFY | HASH | IDENT
    private SyntaxNode cryptoExpr() throws ParseException {
        if (match(TokenType.ENC))  return encExprAfterKeyword();
        if (match(TokenType.MAC))  return macExprAfterKeyword();
        if (match(TokenType.SIGN)) return signExprAfterKeyword();
        if (match(TokenType.VRFY)) return verifyExprAfterKeyword();
        if (match(TokenType.HASH)) return hashExprAfterKeyword();

        if (check(TokenType.IDENTIFIER)) {
            return identifier("Expected identifier in expression.");
        }

        throw error(peek(), "Expected expression (identifier, Enc(...), Mac(...), Sign(...), Vrfy(...), Hash(...)).");
    }

    // encExpr → "Enc" "(" expr "," expr ")" ;
    private SyntaxNode encExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Enc'.");
        SyntaxNode keyExpr = expr();
        consume(TokenType.COMMA, "Expected ',' between key and message inside Enc(key, msg).");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Enc(...).");

        if (!(keyExpr instanceof IdentifierNode keyId)) {
            throw error(previous(), "Encryption key must be an identifier (example: Enc(Kab, m)).");
        }
        return new EncryptExprNode(keyId, msgExpr);
    }

    // macExpr → "Mac" "(" IDENT "," expr ")" ;
    private SyntaxNode macExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Mac'.");
        IdentifierNode key = identifier("Expected MAC key identifier (example: Mac(Kab, m)).");
        consume(TokenType.COMMA, "Expected ',' between key and message inside Mac(key, msg).");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Mac(...).");
        return new MacExprNode(key, msgExpr);
    }

    // hashExpr → "Hash" "(" expr ")" ;
    private SyntaxNode hashExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Hash'.");
        SyntaxNode inner = expr();
        consume(TokenType.RPAREN, "Expected ')' after Hash(...).");
        return new HashExprNode(inner);
    }

    // signExpr → "Sign" "(" IDENT "," expr ")" ;
    private SyntaxNode signExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Sign'.");
        IdentifierNode sk = identifier("Expected signing key identifier (example: Sign(skA, m)).");
        consume(TokenType.COMMA, "Expected ',' between signing key and message inside Sign(key, msg).");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Sign(...).");
        return new SignExprNode(sk, msgExpr);
    }

    // verifyExpr → "Vrfy" "(" IDENT "," expr "," expr ")" ;
    private SyntaxNode verifyExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Vrfy'.");
        IdentifierNode pk = identifier("Expected public key identifier (example: Vrfy(pkA, m, sig)).");
        consume(TokenType.COMMA, "Expected ',' after public key in Vrfy(key, msg, sig).");
        SyntaxNode msgExpr = expr();
        consume(TokenType.COMMA, "Expected ',' after message in Vrfy(key, msg, sig).");
        SyntaxNode sigExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Vrfy(...).");
        return new VerifyExprNode(pk, msgExpr, sigExpr);
    }

    // --------------------------------------------------------------------
    // Key declarations
    // --------------------------------------------------------------------

    // sharedKeyDecl → "shared" "key" IDENT ":" idList ;
    private KeyDeclNode sharedKeyDecl() throws ParseException {
        consume(TokenType.KEY, "Expected 'key' after 'shared' (example: shared key Kab: Alice, Bob).");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'shared key'.");
        consume(TokenType.COLON, "Expected ':' after shared key name.");
        List<String> owners = idList("Expected at least one owner role after ':'.");
        return new KeyDeclNode(KeyKind.SHARED, keyIdent.getLexeme(), owners);
    }

    // publicKeyDecl → "public" "key" IDENT ":" IDENT ;
    private KeyDeclNode publicKeyDecl() throws ParseException {
        consume(TokenType.KEY, "Expected 'key' after 'public' (example: public key pkA: Alice).");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'public key'.");
        consume(TokenType.COLON, "Expected ':' after public key name.");
        Token ownerIdent = consume(TokenType.IDENTIFIER, "Expected owner role after ':'.");

        List<String> owners = new ArrayList<>();
        owners.add(ownerIdent.getLexeme());
        return new KeyDeclNode(KeyKind.PUBLIC, keyIdent.getLexeme(), owners);
    }

    // privateKeyDecl → "private" "key" IDENT ":" IDENT ;
    private KeyDeclNode privateKeyDecl() throws ParseException {
        consume(TokenType.KEY, "Expected 'key' after 'private' (example: private key skA: Alice).");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'private key'.");
        consume(TokenType.COLON, "Expected ':' after private key name.");
        Token ownerIdent = consume(TokenType.IDENTIFIER, "Expected owner role after ':'.");

        List<String> owners = new ArrayList<>();
        owners.add(ownerIdent.getLexeme());
        return new KeyDeclNode(KeyKind.PRIVATE, keyIdent.getLexeme(), owners);
    }

    // idList → IDENTIFIER ( "," IDENTIFIER )*
    private List<String> idList(String errIfMissing) throws ParseException {
        List<String> ids = new ArrayList<>();

        if (!check(TokenType.IDENTIFIER)) {
            throw error(peek(), errIfMissing);
        }

        ids.add(consume(TokenType.IDENTIFIER, "Expected identifier.").getLexeme());
        while (match(TokenType.COMMA)) {
            ids.add(consume(TokenType.IDENTIFIER, "Expected identifier after ','.").getLexeme());
        }
        return ids;
    }

    // --------------------------------------------------------------------
    // Helpers
    // --------------------------------------------------------------------

    private IdentifierNode identifier(String err) throws ParseException {
        Token t = consume(TokenType.IDENTIFIER, err);
        return new IdentifierNode(t.getLexeme());
    }

    private boolean match(TokenType type) {
        if (check(type)) {
            advance();
            return true;
        }
        return false;
    }

    private Token consume(TokenType type, String message) throws ParseException {
        if (check(type)) return advance();
        throw error(peek(), message);
    }

    private ParseException error(Token token, String message) {
        // IMPORTANT: Your ParseException is (String, Token)
        // and it already formats line+column using token.
        return new ParseException(message, token);
    }

    private boolean check(TokenType type) {
        if (type == TokenType.EOF) {
            return peek().getType() == TokenType.EOF;
        }
        if (isAtEnd()) return false;
        return peek().getType() == type;
    }


    private boolean checkNext(TokenType type) {
        // Safe bounds check
        int next = current + 1;
        if (next >= tokens.size()) return false;
        return tokens.get(next).getType() == type;
    }

    private Token advance() {
        if (!isAtEnd()) current++;
        return previous();
    }

    private boolean isAtEnd() {
        return peek().getType() == TokenType.EOF;
    }

    private Token peek() {
        return tokens.get(current);
    }

    private Token previous() {
        return tokens.get(current - 1);
    }
}