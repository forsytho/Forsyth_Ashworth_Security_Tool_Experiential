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
 * Token categories produced by the lexer.
 * Keep this tiny and specific to today's grammar.
 */
public enum TokenType {

    // Keywords
    ROLES, // principals declaration
    ENC,   // encrypt
    DEC,   // decrypt
    MAC,   // message authentication code
    SIGN,  // signature
    VRFY,  // verify signature
    HASH,  // cryptographic hash
    NONCE, // nonce generation

    SHARED, // shared key declaration
    PUBLIC,
    PRIVATE,
    KEY,
    ASSERT,
    SECRET, 

    // Symbols
    ARROW,  // ->
    COLON,  // :
    COMMA,  // ,
    EQUAL,  // =
    LPAREN, // (
    RPAREN, // )
    CONCAT, // ||
    EOF,    // end of input
    

    // Identifiers: names like Alice, Bob, k, m, c...
    IDENTIFIER
}
