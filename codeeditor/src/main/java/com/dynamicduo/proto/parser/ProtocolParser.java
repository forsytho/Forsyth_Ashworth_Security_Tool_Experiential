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
 * Right now this supports:
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

    private final List<Token> tokens = new ArrayList<>();
    private int current = 0;

    public ProtocolParser(Lexer lexer) {
        // I pull all tokens up front so it is easy to peek / lookahead.
        Token t;
        do {
            t = lexer.nextToken();
            tokens.add(t);
        } while (t.getType() != TokenType.EOF);
    }

    /** Entry point: parse a ProtocolNode or throw ParseException on error. */
    public ProtocolNode parse() throws ParseException {
        // 1) roles: Alice, Bob, Server
        RoleDeclNode roles = rolesDecl();
        ProtocolNode proto = new ProtocolNode(roles);

        // 2) zero or more key declarations
        //    shared key K_AB: Alice, Bob
        //    public key pkA: Alice
        //    private key skA: Alice
        while (check(TokenType.SHARED) || check(TokenType.PUBLIC) || check(TokenType.PRIVATE) || check(TokenType.NONCE)) {
            if (match(TokenType.SHARED)) {
                proto.addKeyDecl(sharedKeyDecl());
            } else if (match(TokenType.PUBLIC)) {
                proto.addKeyDecl(publicKeyDecl());
            } else if (match(TokenType.PRIVATE)) {
                proto.addKeyDecl(privateKeyDecl());
            } else if (match(TokenType.NONCE)) {
                proto.addNonceDecl(nonceDecl());
            }
        }

    // 3) messages
    while (peek().getType() != TokenType.EOF) {
        MessageSendNode msg = message();
        proto.addMessage(msg);
    }
    return proto;
}


    // --------------------------------------------------------------------
    // Top-level pieces
    // --------------------------------------------------------------------

    // rolesDecl → "roles" ":" IDENT ( "," IDENT )* ;
    private RoleDeclNode rolesDecl() throws ParseException {
        consume(TokenType.ROLES, "Expected 'roles' declaration.");
        consume(TokenType.COLON, "Expected ':' after 'roles'.");

        RoleDeclNode roles = new RoleDeclNode();
        roles.addRole(identifier("Expected role name."));

        while (match(TokenType.COMMA)) {
            roles.addRole(identifier("Expected role name after ','."));
        }
        return roles;
    }

    // message → IDENT ARROW IDENT ":" stmt ;
    private MessageSendNode message() throws ParseException {
        IdentifierNode sender = identifier("Expected sender identifier.");
        consume(TokenType.ARROW, "Expected '->' after sender.");
        IdentifierNode receiver = identifier("Expected receiver identifier.");
        consume(TokenType.COLON, "Expected ':' after receiver.");
        SyntaxNode body = stmt();
        return new MessageSendNode(sender, receiver, body);
    }

    // --------------------------------------------------------------------
    // Statements and expressions
    // --------------------------------------------------------------------

    // stmt → IDENT "=" expr | expr ;
    //
    // I allow either an assignment (c = Enc(...)) or a bare expression
    // (just sending a value directly).
    private SyntaxNode stmt() throws ParseException {
        if (check(TokenType.IDENTIFIER) && checkNext(TokenType.EQUAL)) {
            IdentifierNode target = identifier("Expected variable name.");
            consume(TokenType.EQUAL, "Expected '=' after variable.");
            SyntaxNode value = expr();
            return new AssignNode(target, value);
        }
        return expr();
    }

    // expr → concatExpr ;
    //
    // I keep expr() as a separate method in case I want to add more
    // precedence levels later.
    private SyntaxNode expr() throws ParseException {
        return concatExpr();
    }

    // concatExpr → cryptoExpr ( "||" cryptoExpr )* ;
    //
    // I treat "||" as left-associative:
    //   a || b || c parses as Concat(Concat(a, b), c)
    private SyntaxNode concatExpr() throws ParseException {
        SyntaxNode left = cryptoExpr();
        while (match(TokenType.CONCAT)) { // token for "||"
            SyntaxNode right = cryptoExpr();
            left = new ConcatNode(left, right);
        }
        return left;
    }

    // cryptoExpr → encExpr
    //            | macExpr
    //            | signExpr
    //            | verifyExpr
    //            | hashExpr
    //            | IDENT
    //
    // This is the base expression layer where I dispatch based on which
    // crypto keyword appears, or fall back to a bare identifier.
    private SyntaxNode cryptoExpr() throws ParseException {
        if (match(TokenType.ENC)) {
            return encExprAfterKeyword();
        }
        if (match(TokenType.MAC)) {
            return macExprAfterKeyword();
        }
        if (match(TokenType.SIGN)) {
            return signExprAfterKeyword();
        }
        if (match(TokenType.VRFY)) {
            return verifyExprAfterKeyword();
        }
        if (match(TokenType.HASH)) { // "H"
            return hashExprAfterKeyword();
        }

        if (check(TokenType.IDENTIFIER)) {
            return identifier("Expected identifier in expression.");
        }

        throw error(peek(), "Expected expression.");
    }

    // encExpr → "Enc" "(" expr "," expr ")" ;
    //
    // I allow general expressions for key and message, but for now I require
    // the key to be an identifier so the analyzer can treat it as a simple
    // key symbol.
    private SyntaxNode encExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Enc'.");
        SyntaxNode keyExpr = expr();
        consume(TokenType.COMMA, "Expected ',' between key and message inside Enc.");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Enc(...).");

        if (!(keyExpr instanceof IdentifierNode keyId)) {
            throw error(previous(), "Encryption key must be an identifier.");
        }
        return new EncryptExprNode(keyId, msgExpr);
    }

    // macExpr → "Mac" "(" IDENT "," expr ")" ;
    private SyntaxNode macExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Mac'.");
        IdentifierNode key = identifier("Expected MAC key identifier.");
        consume(TokenType.COMMA, "Expected ',' between key and message inside Mac.");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Mac(...).");
        return new MacExprNode(key, msgExpr);
    }

    // hashExpr → "H" "(" expr ")" ;
    private SyntaxNode hashExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'H'.");
        SyntaxNode inner = expr();
        consume(TokenType.RPAREN, "Expected ')' after H(...).");
        return new HashExprNode(inner);
    }

    // signExpr → "Sign" "(" IDENT "," expr ")" ;
    private SyntaxNode signExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Sign'.");
        IdentifierNode sk = identifier("Expected signing key identifier.");
        consume(TokenType.COMMA, "Expected ',' between signing key and message inside Sign.");
        SyntaxNode msgExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Sign(...).");
        return new SignExprNode(sk, msgExpr);
    }

    // verifyExpr → "Verify" "(" IDENT "," expr "," expr ")" ;
    private SyntaxNode verifyExprAfterKeyword() throws ParseException {
        consume(TokenType.LPAREN, "Expected '(' after 'Verify'.");
        IdentifierNode pk = identifier("Expected public key identifier.");
        consume(TokenType.COMMA, "Expected ',' after public key in Verify.");
        SyntaxNode msgExpr = expr();
        consume(TokenType.COMMA, "Expected ',' after message in Verify.");
        SyntaxNode sigExpr = expr();
        consume(TokenType.RPAREN, "Expected ')' after Verify(...).");
        return new VerifyExprNode(pk, msgExpr, sigExpr);
    }

    // sharedKeyDecl → "shared" "key" IDENTIFIER ":" idList ;
    private KeyDeclNode sharedKeyDecl() throws ParseException {
        // we have already consumed 'shared'
        consume(TokenType.KEY, "Expected 'key' after 'shared'.");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'shared key'.");
        consume(TokenType.COLON, "Expected ':' after shared key name.");
        List<String> owners = idList();
        return new KeyDeclNode(KeyKind.SHARED, keyIdent.getLexeme(), owners);
    }

    // publicKeyDecl → "public" "key" IDENTIFIER ":" IDENTIFIER ;
    private KeyDeclNode publicKeyDecl() throws ParseException {
        // we have already consumed 'public'
        consume(TokenType.KEY, "Expected 'key' after 'public'.");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'public key'.");
        consume(TokenType.COLON, "Expected ':' after public key name.");
        Token ownerIdent = consume(TokenType.IDENTIFIER, "Expected owner role after ':'.");
        List<String> owners = new ArrayList<>();
        owners.add(ownerIdent.getLexeme());
        return new KeyDeclNode(KeyKind.PUBLIC, keyIdent.getLexeme(), owners);
    }

    // privateKeyDecl → "private" "key" IDENTIFIER ":" IDENTIFIER ;
    private KeyDeclNode privateKeyDecl() throws ParseException {
        // we have already consumed 'private'
        consume(TokenType.KEY, "Expected 'key' after 'private'.");
        Token keyIdent = consume(TokenType.IDENTIFIER, "Expected key name after 'private key'.");
        consume(TokenType.COLON, "Expected ':' after private key name.");
        Token ownerIdent = consume(TokenType.IDENTIFIER, "Expected owner role after ':'.");
        List<String> owners = new ArrayList<>();
        owners.add(ownerIdent.getLexeme());
        return new KeyDeclNode(KeyKind.PRIVATE, keyIdent.getLexeme(), owners);
    }

    // nonceDecl → "nonce" IDENTIFIER ":" IDENTIFIER ;
    private NonceDeclNode nonceDecl() throws ParseException {
        // we have already consumed 'nonce'
        Token nonceIdent = consume(TokenType.IDENTIFIER, "Expected nonce name after 'nonce'.");
        consume(TokenType.COLON, "Expected ':' after nonce name.");
        Token ownerIdent = consume(TokenType.IDENTIFIER, "Expected owner role after ':'.");
        return new NonceDeclNode(nonceIdent.getLexeme(), ownerIdent.getLexeme());
    }

    
    // idList → IDENTIFIER ( "," IDENTIFIER )*
    private List<String> idList() throws ParseException {
        List<String> ids = new ArrayList<>();
        Token first = consume(TokenType.IDENTIFIER, "Expected identifier.");
        ids.add(first.getLexeme());
        while (match(TokenType.COMMA)) {
            Token t = consume(TokenType.IDENTIFIER, "Expected identifier after ','.");
            ids.add(t.getLexeme());
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
        if (check(type))
            return advance();
        throw error(peek(), message);
    }

    private ParseException error(Token token, String message) {
        return new ParseException(message + " Found: " + token, token.getLine());
    }

    private boolean check(TokenType type) {
        if (isAtEnd())
            return false;
        return peek().getType() == type;
    }

    private boolean checkNext(TokenType type) {
        if (isAtEnd())
            return false;
        if (tokens.get(current).getType() == TokenType.EOF)
            return false;
        return tokens.get(current + 1).getType() == type;
    }

    private Token advance() {
        if (!isAtEnd())
            current++;
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
