package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;

import java.util.*;

/**
 * Layer 1 warnings:
 * 1) A signature created as:  sig = Sign(sk, msg)  but never verified later via: Vrfy(pk, msg, sig)
 * 2) A verification uses: Vrfy(..., sig) but sig was never created earlier using Sign(...)
 *
 */
public final class VerificationWarningAnalyzer {

    private VerificationWarningAnalyzer() {}

    public static List<String> analyze(ProtocolNode proto) {
        List<String> warnings = new ArrayList<>();

        // signatureVar -> where it was created (message context)
        Map<String, String> createdSignatures = new LinkedHashMap<>();
        Set<String> verifiedSignatures = new HashSet<>();

        List<MessageSendNode> messages = proto.getMessages();

        // Pass 1: find "sig = Sign(...)"
        for (int i = 0; i < messages.size(); i++) {
            MessageSendNode msg = messages.get(i);
            String ctx = context(msg, i);
            collectSignatureCreations(msg.getBody(), ctx, createdSignatures);
        }

        // Pass 2: find "Vrfy(..., sig)"
        for (int i = 0; i < messages.size(); i++) {
            MessageSendNode msg = messages.get(i);
            collectVerifications(msg.getBody(), verifiedSignatures, warnings, createdSignatures);
        }

        // Pass 3: warn created but never verified
        for (Map.Entry<String, String> e : createdSignatures.entrySet()) {
            String sigName = e.getKey();
            String ctx = e.getValue();
            if (!verifiedSignatures.contains(sigName)) {
                warnings.add(" Missing verification: signature '" + sigName
                        + "' was created (" + ctx + ") but is never verified with Vrfy(...).");
            }
        }

        if (warnings.isEmpty()) warnings.add("No warnings.");
        return warnings;
    }

    private static void collectSignatureCreations(
            SyntaxNode node,
            String ctx,
            Map<String, String> created
    ) {
        if (node == null) return;

        // sig = Sign(sk, msg)
        if (node instanceof AssignNode a) {
            SyntaxNode rhs = a.getValue();
            if (rhs instanceof SignExprNode) {
                String sigVar = a.getTarget().getName();
                created.putIfAbsent(sigVar, ctx);
            }

            // Recurse into the RHS
            collectSignatureCreations(a.getValue(), ctx, created);
            return;
        }

        // Generic recursion
        for (SyntaxNode child : node.children()) {
            collectSignatureCreations(child, ctx, created);
        }
    }

    private static void collectVerifications(
            SyntaxNode node,
            Set<String> verified,
            List<String> warnings,
            Map<String, String> created
    ) {
        if (node == null) return;

        if (node instanceof VerifyExprNode v) {
            SyntaxNode sigExpr = v.getSignature();

            // Track precise cases: Vrfy(..., sig) where sig is an IdentifierNode
            if (sigExpr instanceof IdentifierNode id) {
                String sigName = id.getName();
                verified.add(sigName);

                if (!created.containsKey(sigName)) {
                    warnings.add("Verification uses signature '" + sigName
                            + "', but no earlier assignment like '" + sigName + " = Sign(...)' was found.");
                }
            }
        }

        for (SyntaxNode child : node.children()) {
            collectVerifications(child, verified, warnings, created);
        }
    }

    private static String context(MessageSendNode msg, int index) {
        return "message " + (index + 1) + ": "
                + msg.getSender().getName() + " -> " + msg.getReceiver().getName();
    }
}
