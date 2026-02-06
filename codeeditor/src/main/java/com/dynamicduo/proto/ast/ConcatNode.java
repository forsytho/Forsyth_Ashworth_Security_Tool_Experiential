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
 * ConcatNode: left || right
 */
public final class ConcatNode extends SyntaxNode {
    private final SyntaxNode left;
    private final SyntaxNode right;

    public ConcatNode(SyntaxNode left, SyntaxNode right) {
        this.left = left;
        this.right = right;
    }

    public SyntaxNode getLeft()  { return left; }
    public SyntaxNode getRight() { return right; }

    @Override
    public String label() {
        return "(" + left.label() + " || " + right.label() + ")";
    }


    @Override
    public List<SyntaxNode> children() {
        return List.of(left, right);
    }
}
