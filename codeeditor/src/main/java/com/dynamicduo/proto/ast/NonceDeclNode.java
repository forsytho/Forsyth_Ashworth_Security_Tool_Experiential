package com.dynamicduo.proto.ast;

public final class NonceDeclNode extends SyntaxNode {
    private final String name;
    private final String owner;

    public NonceDeclNode(String name, String owner) {
        this.name = name;
        this.owner = owner;
    }

    public String getName() {
        return name;
    }

    public String getOwner() {
        return owner;
    }

    @Override
    public String label() {
        return "NonceDecl";
    }

}