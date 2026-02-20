package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;

import java.util.*;

/**
 * Key misuse warnings (Layer 1):
 * - Enc(key, ...) should use a SHARED key
 * - Mac(key, ...) should use a SHARED key
 * - Sign(sk, ...) should use a PRIVATE key
 * - Vrfy/Verify(pk, ...) should use a PUBLIC key
 * - Warn on undeclared keys used in crypto operations
 */
public final class KeyMisuseWarningAnalyzer {

    private KeyMisuseWarningAnalyzer() {}

    public static List<String> analyze(ProtocolNode proto) {
        List<String> warnings = new ArrayList<>();

        Map<String, KeyKind> keyKinds = buildKeyKindTable(proto);

        List<MessageSendNode> msgs = proto.getMessages();
        for (int i = 0; i < msgs.size(); i++) {
            MessageSendNode msg = msgs.get(i);
            String ctx = context(msg, i);
            checkNode(msg.getBody(), keyKinds, warnings, ctx);
        }

        if (warnings.isEmpty()) warnings.add("No key-misuse warnings.");
        return warnings;
    }

    private static void checkNode(
            SyntaxNode node,
            Map<String, KeyKind> keyKinds,
            List<String> warnings,
            String ctx
    ) {
        if (node == null) return;

        // Enc(key, msg) -> SHARED
        if (node instanceof EncryptExprNode enc) {
            IdentifierNode key = enc.getKey();
            if (key != null) {
                checkKeyKind(key.getName(), KeyKind.SHARED, "Enc", keyKinds, warnings, ctx);
            }
        }

        // Mac(key, msg) -> SHARED
        if (node instanceof MacExprNode mac) {
            IdentifierNode key = mac.getKey();
            if (key != null) {
                checkKeyKind(key.getName(), KeyKind.SHARED, "Mac", keyKinds, warnings, ctx);
            }
        }

        // Sign(sk, msg) -> PRIVATE
        if (node instanceof SignExprNode sign) {
            IdentifierNode sk = sign.getSigningKey();
            if (sk != null) {
                checkKeyKind(sk.getName(), KeyKind.PRIVATE, "Sign", keyKinds, warnings, ctx);
            }
        }

        // Verify(pk, msg, sig) -> PUBLIC
        if (node instanceof VerifyExprNode ver) {
            IdentifierNode pk = ver.getPublicKey();
            if (pk != null) {
                checkKeyKind(pk.getName(), KeyKind.PUBLIC, "Vrfy/Verify", keyKinds, warnings, ctx);
            }
        }

        // Recurse
        for (SyntaxNode child : node.children()) {
            checkNode(child, keyKinds, warnings, ctx);
        }
    }

    private static Map<String, KeyKind> buildKeyKindTable(ProtocolNode proto) {
        Map<String, KeyKind> map = new HashMap<>();
        for (KeyDeclNode kd : proto.getKeyDecls()) {
            map.put(kd.getKeyName(), kd.getKind());
        }
        return map;
    }

    private static void checkKeyKind(
            String keyName,
            KeyKind expected,
            String op,
            Map<String, KeyKind> keyKinds,
            List<String> warnings,
            String ctx
    ) {
        KeyKind actual = keyKinds.get(keyName);

        if (actual == null) {
            warnings.add("Undeclared key: '" + keyName + "' used in " + op + "(...) (" + ctx + ").");
            return;
        }

        if (actual != expected) {
            warnings.add("Key misuse: '" + keyName + "' is declared as " + actual
                    + " but used in " + op + "(...) where a " + expected + " key is expected (" + ctx + ").");
        }
    }

    private static String context(MessageSendNode msg, int index) {
        return "message " + (index + 1) + ": "
                + msg.getSender().getName() + " -> " + msg.getReceiver().getName();
    }
}
