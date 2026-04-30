package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;

import java.util.*;

/**
 * AuthenticationWarningAnalyzer
 *
 * Detects protocols that contain message passing but no authentication
 * mechanism (no Sign(...) or Verify(...)).
 * 
 * Rationale:
 * - Without authentication, protocols are vulnerable to MITM attacks
 * - Even if encryption is used correctly, identity is not guaranteed
 */
public final class AuthenticationWarningAnalyzer {

    private AuthenticationWarningAnalyzer() {}

    public static List<String> analyze(ProtocolNode proto) {
        List<String> warnings = new ArrayList<>();

        boolean hasAuthentication = false;

        // Scan all messages for Sign or Verify usage
        for (MessageSendNode msg : proto.getMessages()) {
            if (containsAuth(msg.getBody())) {
                hasAuthentication = true;
                break;
            }
        }

        // If protocol has messages but no authentication → warn
        if (!proto.getMessages().isEmpty() && !hasAuthentication) {
            warnings.add("No authentication mechanism detected. Protocol may be vulnerable to Man-in-the-Middle (MITM) attacks.");
        } else {
            warnings.add("Authentication mechanism present.");
        }

        return warnings;
    }

    private static boolean containsAuth(SyntaxNode node) {
        if (node == null) return false;

        if (node instanceof SignExprNode) return true;
        if (node instanceof VerifyExprNode) return true;

        List<SyntaxNode> children = node.children();
        if (children == null) return false;

        for (SyntaxNode child : children) {
            if (containsAuth(child)) return true;
        }

        return false;
    }
}