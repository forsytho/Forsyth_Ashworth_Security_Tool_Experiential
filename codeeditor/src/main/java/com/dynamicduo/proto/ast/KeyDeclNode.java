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

package com.dynamicduo.proto.ast;

import java.util.List;

/**
 * KeyDeclNode: key declarations
 */
public final class KeyDeclNode extends SyntaxNode {
    private final KeyKind kind;
    private final String keyName;
    private final List<String> owners; // e.g. ["Alice", "Bob"] or ["Alice"]

    public KeyDeclNode(KeyKind kind, String keyName, List<String> owners) {
        this.kind = kind;
        this.keyName = keyName;
        this.owners = owners;
    }

    public KeyKind getKind() { return kind; }

    public String getKeyName() { return keyName; }

    public List<String> getOwners() { return owners; }

    @Override
    public String label() { return kind + ": " + keyName; }
}
