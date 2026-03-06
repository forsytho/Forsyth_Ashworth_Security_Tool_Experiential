package com.dynamicduo.proto.ast;

import java.util.List;

public final class CertDeclNode extends SyntaxNode {
    private final String publicKeyName;
    private final String owner;

    public CertDeclNode(String publicKeyName, String owner) {
        this.publicKeyName = publicKeyName;
        this.owner = owner;
    }

    public String getPublicKeyName() {
        return publicKeyName;
    }

    public String getOwner() {
        return owner;
    }

    @Override
    public String label() {
        return "cert " + publicKeyName + ": " + owner;
    }

    @Override
    public List<SyntaxNode> children() {
        return List.of();
    }
}