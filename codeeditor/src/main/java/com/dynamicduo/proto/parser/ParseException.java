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

package com.dynamicduo.proto.parser;
import com.dynamicduo.proto.lexer.Token;

/** Thrown when the parser hits unexpected tokens. */
public class ParseException extends Exception {
    public final Token token;

    public ParseException(String message, Token token) {
        super(message);
        this.token = token;
    }

    @Override
    public String getMessage() {
        if (token == null) {
            return super.getMessage();
        }
        return String.format(
            "Syntax error at line %d, column %d: %s (found '%s')",
            token.getLine(),
            token.getColumn(),
            super.getMessage(),
            token.getLexeme()
        );
    }
}

