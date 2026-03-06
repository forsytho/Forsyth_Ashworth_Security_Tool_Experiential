package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;

import java.util.*;

/**
 * SignatureForgeryAnalysis
 *
 * Purpose:
 * 1) Detect when verification is performed using a public key that is not
 *    certified/bound to an identity.
 *
 * 2) Detect when signature forgery is possible because the adversary knows
 *    a private signing key.
 *
 * Assumptions:
 * - Certificates are modeled by KnowledgeResult.certifiedKeyOwners():
 *       publicKeyName -> ownerRole
 * - Public/private key ownership comes from KeyDeclNode declarations
 * - Verify(...) is treated as a protocol step / semantic event
 */
public final class SignatureForgeryAnalysis {

    private static final String ADVERSARY = "Adversary";

    private SignatureForgeryAnalysis() {}

    public static List<String> analyze(ProtocolNode proto, KnowledgeResult result) {
        LinkedHashSet<String> warnings = new LinkedHashSet<>();

        Map<String, String> privateKeyOwner = buildPrivateKeyOwnerTable(proto);
        Map<String, String> publicKeyOwner = buildPublicKeyOwnerTable(proto);

        Set<String> adversaryKnows = result.knows().getOrDefault(ADVERSARY, Set.of());

        // 1) If adversary knows any private signing key, signatures under that key are forgeable
        for (Map.Entry<String, String> entry : privateKeyOwner.entrySet()) {
            String sk = entry.getKey();
            String owner = entry.getValue();

            if (adversaryKnows.contains(sk)) {
                warnings.add("Forgery risk: adversary knows private key '" + sk +
                        "' (owner: " + owner + "), so signatures as " + owner + " are forgeable.");
            }
        }

        // 2) Walk protocol messages and inspect Sign / Verify uses
        List<MessageSendNode> messages = proto.getMessages();
        for (int i = 0; i < messages.size(); i++) {
            MessageSendNode msg = messages.get(i);
            String ctx = context(msg, i);

            // Verify(...) checks
            collectVerifyWarnings(
                    msg.getBody(),
                    result.certifiedKeyOwners(),
                    publicKeyOwner,
                    warnings,
                    ctx
            );

            // Sign(...) checks
            collectSignWarnings(
                    msg.getBody(),
                    msg.getSender().getName(),
                    privateKeyOwner,
                    adversaryKnows,
                    warnings,
                    ctx
            );
        }

        if (warnings.isEmpty()) {
            warnings.add("No signature-forgery issues detected.");
        }

        return new ArrayList<>(warnings);
    }

    // --------------------------------------------------------------------
    // Verify(...) analysis
    // --------------------------------------------------------------------

    private static void collectVerifyWarnings(
            SyntaxNode node,
            Map<String, String> certifiedKeyOwners,   // pk -> certified owner
            Map<String, String> publicKeyOwner,       // pk -> declared owner
            Set<String> warnings,
            String ctx
    ) {
        if (node == null) return;

        if (node instanceof VerifyExprNode verify) {
            IdentifierNode pkNode = verify.getPublicKey();
            if (pkNode != null) {
                String pk = pkNode.getName();

                String certifiedOwner = certifiedKeyOwners.get(pk);
                String declaredOwner  = publicKeyOwner.get(pk);

                if (certifiedOwner == null) {
                    if (declaredOwner != null) {
                        warnings.add("Key-substitution risk: verification uses public key '" + pk +
                                "' (declared owner: " + declaredOwner +
                                ") without a certificate binding (" + ctx + ").");
                    } else {
                        warnings.add("Key-substitution risk: verification uses undeclared or uncertified public key '" +
                                pk + "' (" + ctx + ").");
                    }
                }
            }
        }

        for (SyntaxNode child : node.children()) {
            collectVerifyWarnings(child, certifiedKeyOwners, publicKeyOwner, warnings, ctx);
        }
    }

    // --------------------------------------------------------------------
    // Sign(...) analysis
    // --------------------------------------------------------------------

    private static void collectSignWarnings(
            SyntaxNode node,
            String sender,
            Map<String, String> privateKeyOwner,   // sk -> owner
            Set<String> adversaryKnows,
            Set<String> warnings,
            String ctx
    ) {
        if (node == null) return;

        if (node instanceof SignExprNode sign) {
            IdentifierNode skNode = sign.getSigningKey();
            if (skNode != null) {
                String sk = skNode.getName();
                String owner = privateKeyOwner.get(sk);

                // Suspicious: sender is using someone else's declared private key
                if (owner != null && !owner.equals(sender)) {
                    warnings.add("Suspicious signing step: " + sender +
                            " uses private key '" + sk + "' owned by " + owner +
                            " (" + ctx + ").");
                }

                // Extra local warning if this exact signing key is already compromised
                if (adversaryKnows.contains(sk)) {
                    warnings.add("Forgery risk: signature uses compromised private key '" + sk +
                            "' (" + ctx + ").");
                }
            }
        }

        for (SyntaxNode child : node.children()) {
            collectSignWarnings(child, sender, privateKeyOwner, adversaryKnows, warnings, ctx);
        }
    }

    // --------------------------------------------------------------------
    // Key ownership tables
    // --------------------------------------------------------------------

    private static Map<String, String> buildPrivateKeyOwnerTable(ProtocolNode proto) {
        Map<String, String> map = new LinkedHashMap<>();

        for (KeyDeclNode kd : proto.getKeyDecls()) {
            if (kd.getKind() == KeyKind.PRIVATE && !kd.getOwners().isEmpty()) {
                map.put(kd.getKeyName(), kd.getOwners().get(0));
            }
        }

        return map;
    }

    private static Map<String, String> buildPublicKeyOwnerTable(ProtocolNode proto) {
        Map<String, String> map = new LinkedHashMap<>();

        for (KeyDeclNode kd : proto.getKeyDecls()) {
            if (kd.getKind() == KeyKind.PUBLIC && !kd.getOwners().isEmpty()) {
                map.put(kd.getKeyName(), kd.getOwners().get(0));
            }
        }

        return map;
    }

    private static String context(MessageSendNode msg, int index) {
        return "message " + (index + 1) + ": "
                + msg.getSender().getName() + " -> " + msg.getReceiver().getName();
    }
}