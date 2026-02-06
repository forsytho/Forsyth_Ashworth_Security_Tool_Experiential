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

package com.dynamicduo.proto.ast;

import java.util.ArrayList;
import java.util.List;

/**
 * Root of the AST.
 * Holds the role declarations and the list of message sends.
 */
public class ProtocolNode extends SyntaxNode {
    private final RoleDeclNode roles;
    private final List<MessageSendNode> messages = new ArrayList<>();
    private final List<KeyDeclNode> keyDecls = new ArrayList<>();
    private final List<NonceDeclNode> nonceDecls = new ArrayList<>();

    public ProtocolNode(RoleDeclNode roles) {
        this.roles = roles;
    }

    public void addMessage(MessageSendNode msg) {
        messages.add(msg);
    }

    public RoleDeclNode getRoles() {
        return roles;
    }

    public List<MessageSendNode> getMessages() {
        return messages;
    }

    public List<KeyDeclNode> getKeyDecls() {
        return keyDecls;
    }

    public void addKeyDecl(KeyDeclNode decl) {
        keyDecls.add(decl);
    }

    public List<NonceDeclNode> getNonceDecls() {
        return nonceDecls;
    }

    public void addNonceDecl(NonceDeclNode decl) {
        nonceDecls.add(decl);
    }

    @Override
    public String label() {
        return "Protocol";
    }

    @Override
    public List<SyntaxNode> children() {
        List<SyntaxNode> c = new ArrayList<>();
        c.add(roles);
        c.addAll(messages);
        return c;
    }
}
