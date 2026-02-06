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

package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.*;

import java.util.*;

/**
 * KnowledgeAnalyzer
 *
 * Goal:
 * Given a protocol AST (ProtocolNode), estimate what each principal
 * (Alice, Bob, etc.) and an implicit eavesdropper ("Adversary")
 * knows after a single run of the protocol.
 *
 * What this track:
 *   - For each principal P:
 *       knows[P]       = set of atomic terms P knows (K_AB, N_A, M_1, c, ...)
 *       cryptoTerms[P] = set of opaque structured terms P has seen
 *                        ("Enc(K_AB, M_1)", "Mac(K_AB, c)", "Concatenation(m1, 0)", ...)
 *
 * Semantic model (more “computational” than pure symbolic):
 *
 *   - When P sends or receives a message, P "sees":
 *       * identifiers that appear in the clear (not under crypto),
 *       * opaque crypto terms (Enc, Mac, H, Sign, Verify, Concat, ...).
 *
 *   - The adversary is assumed to see ALL messages (passive eavesdropper).
 *
 *   - Ciphertexts, MACs, hashes, signatures, and concatenations are opaque:
 *       * Seeing Enc(k, m) does not automatically reveal k or m.
 *       * Seeing m1 || 0 in the clear is treated as a single opaque Concat(...)
 *         term, not as separate identifiers m1 and 0.
 *
 *   - Decryption rule:
 *       If P knows Enc(k, m) (as an opaque term) and also knows k (from
 *       somewhere else as an identifier), then P learns m as a symbolic
 *       identifier.
 */
public final class KnowledgeAnalyzer {

    // Label for the implicit eavesdropping adversary.
    private static final String ADVERSARY = "Adversary";
    private record EncTerm(String keyName, SyntaxNode plaintext) {}


    private KnowledgeAnalyzer() {
        // Utility class
    }

    /**
     * Public entry point.
     *
     * Typical usage from a demo:
     *     KnowledgeAnalyzer.analyzeAndPrint(tree);
     *
     * This prints the knowledge summary to stdout.
     * The heavy lifting is done in analyzeToString().
     */
    public static void analyzeAndPrint(ProtocolNode proto) {
        System.out.print(analyzeToString(proto));
    }


    /**
     * Walk a SyntaxNode subtree and extract:
     *  - identifiers that appear in the clear (lhs of assignments, bare ids, and
     *    any opaque crypto/concat terms we want to list in the summary)
     *  - ciphertext terms "Enc(keySym, msgSym)" as opaque units in encrypts
     *
     * Visibility rules:
     *  - Bare identifiers: visible in the clear.
     *  - Assignment "x = expr": the variable x is visible; visibility of expr
     *    depends on Recursion + node-specific rules.
     *  - Enc(key, msgExpr): we record only the ciphertext symbol
     *      Enc(keyName, msgLabel)
     *    in encrypts; no visibility of msgExpr’s internals.
     *  - Mac, Hash, Sign, Verify: treated as opaque symbols, added to identifiers
     *    so they appear in the knowledge summary but do not enable inference.
     */
    private static void collectTerms(
            SyntaxNode node,
            Set<String> identifiers,
            Set<EncTerm> encrypts) {

        // Bare identifier in the clear.
        if (node instanceof IdentifierNode id) {
            identifiers.add(id.getName());
        }

        // Encryption: Enc(keyExpr, msgExpr)
        else if (node instanceof EncryptExprNode enc) {
            String kName = enc.getKey().getName();

            // Store the actual plaintext AST (so we can open concat after decrypt)
            encrypts.add(new EncTerm(kName, enc.getMessage()));
        }

        // Concatenation: left || right
        else if (node instanceof ConcatNode cat) {
            // Optional: keep a readable “whole thing” symbol for display
            String sym = "(" + cat.getLeft().label() + " || " + cat.getRight().label() + ")";
            identifiers.add(sym);

            // FIX: concatenation is transparent on the wire
            collectTerms(cat.getLeft(), identifiers, encrypts);
            collectTerms(cat.getRight(), identifiers, encrypts);
        }   

        // MAC: Mac(keyId, msgExpr)
        else if (node instanceof MacExprNode mac) {
            String kName   = mac.getKey().getName();
            String msgSym  = mac.getMessage().label();
            String sym = "Mac(" + kName + ", " + msgSym + ")";

            // Include the MAC tag as a visible symbol, but no inference is built on it.
            identifiers.add(sym);
            // No recursion into msgExpr for visibility.
        }

        // Hash: Hash(expr)
        else if (node instanceof HashExprNode h) {
            String inner = h.getInner().label();
            String sym = "H(" + inner + ")";

            identifiers.add(sym);
            // Do not recurse into inner for visibility.
        }

        // Signature: Sign(sk, msgExpr)
        else if (node instanceof SignExprNode s) {
            String skName  = s.getSigningKey().getName();
            String msgSym  = s.getMessage().label();
            String sym = "Sign(" + skName + ", " + msgSym + ")";

            identifiers.add(sym);
        }

        // Verify: Verify(pk, msgExpr, sigExpr)
        else if (node instanceof VerifyExprNode v) {
            String pkName   = v.getPublicKey().getName();
            String msgSym   = v.getMessage().label();
            String sigSym   = v.getSignature().label();
            String sym = "Verify(" + pkName + ", " + msgSym + ", " + sigSym + ")";

            identifiers.add(sym);
        }

        // Assignment: exposes the LHS variable in the clear,
        // then applies the visibility rules recursively to the RHS.
        else if (node instanceof AssignNode a) {
            identifiers.add(a.getTarget().getName());
            collectTerms(a.getValue(), identifiers, encrypts);
        }


    }


    /**
     * Main knowledge analysis function.
     *
     * Given a ProtocolNode AST, returns a pretty-printed string
     * summarizing what each principal (and the adversary) knows
     * after one run of the protocol.
     */
    public static String analyzeToString(ProtocolNode proto) {

        Map<String, Set<String>> knows = new LinkedHashMap<>();
        Map<String, Set<EncTerm>> encryptTerms = new LinkedHashMap<>();

        // 1) Initialize knowledge map for all declared roles in the protocol.
        for (IdentifierNode id : proto.getRoles().getRoles()) {
            knows.put(id.getName(), new LinkedHashSet<>());
        }
        // Add the implicit passive adversary.
        knows.put(ADVERSARY, new LinkedHashSet<>());

        // Build a map of keyName -> KeyKind for easy lookup
        Map<String, KeyKind> keyKinds = new HashMap<>();
        for (KeyDeclNode kd : proto.getKeyDecls()) {
            keyKinds.put(kd.getKeyName(), kd.getKind());
        }

        // For identifying secrets later
       Set<String> secretKeys = new HashSet<>();
        for (Map.Entry<String, KeyKind> entry : keyKinds.entrySet()) {
            if (entry.getValue() == KeyKind.SHARED || entry.getValue() == KeyKind.PRIVATE) {
                secretKeys.add(entry.getKey());
            }
        }

        // 2) Seed knowledge from key declarations
        for (KeyDeclNode kd : proto.getKeyDecls()) {
            String keyName = kd.getKeyName();
            switch (kd.getKind()) {
                case SHARED:
                    // shared key known only to owners
                    for (String owner : kd.getOwners()) {
                        if (knows.containsKey(owner)) {
                            knows.get(owner).add(keyName);
                        }
                    }
                    break;

                case PUBLIC:
                    // public key known to all principals (roles + adversary)
                    for (String principal : knows.keySet()) {
                        knows.get(principal).add(keyName);
                    }
                    break;

                case PRIVATE:
                    // private key known only to owner(s)
                    for (String owner : kd.getOwners()) {
                        if (knows.containsKey(owner)) {
                            knows.get(owner).add(keyName);
                        }
                    }
                    break;
            }
        }

        // 2.5) Seed knowledge from nonce declarations: nonce known only to its owner (generator)
        for (NonceDeclNode nd : proto.getNonceDecls()) {
            String nonceName = nd.getName();
            String owner = nd.getOwner();
            if (knows.containsKey(owner)) {
                knows.get(owner).add(nonceName);
            }
        }


        // 3) Initialize encryptTerms map (opaque Enc(...) terms per principal)
        for (String p : knows.keySet()) {
            encryptTerms.put(p, new LinkedHashSet<>());
        }

        // 4) Collect terms from messages
        for (MessageSendNode msg : proto.getMessages()) {
            String sender = msg.getSender().getName();
            String recv   = msg.getReceiver().getName();
            List<String> observers = List.of(sender, recv, ADVERSARY);

            // 4.1) What is visible on the wire (existing visibility rules)
            Set<String> visibleIds = new LinkedHashSet<>();
            Set<EncTerm> encs       = new LinkedHashSet<>();
            collectTerms(msg.getBody(), visibleIds, encs);

            // 4.2) What the sender must know to BUILD this message (keys, nonces, etc.)
            Set<String> builtIds = new LinkedHashSet<>();
            collectAuthorIds(msg.getBody(), builtIds);

            // Observers learn only what is visible on the wire
            for (String p : observers) {
                knows.get(p).addAll(visibleIds);
                encryptTerms.get(p).addAll(encs);
            }

            // Sender also knows all identifiers used to construct the message
            if (knows.containsKey(sender)) {
                knows.get(sender).addAll(builtIds);
            }
        }

        // 5) Apply decryption rule until no new knowledge is added.
        boolean changed;
        do {

            changed = false;
            for (String p : knows.keySet()) {
                Set<String> terms = knows.get(p);
                Set<EncTerm> encs = encryptTerms.get(p);

                for (EncTerm enc : encs) {

                    String k = enc.keyName();
                    SyntaxNode plaintext = enc.plaintext();

                    // If encryption used a PUBLIC key, require matching PRIVATE key to decrypt
                    String requiredKey = k;
                    KeyKind kind = keyKinds.get(k);
                    if (kind == KeyKind.PUBLIC) {
                        String sk = matchingPrivateKeyName(k); // pkX -> skX
                        if (sk != null) requiredKey = sk;
                    }

                    if (canDecrypt(terms, requiredKey, keyKinds)) {
                        if (learnFromDecryptedPlaintext(plaintext, terms)) {
                            changed = true;
                        }
                    }
                }

            }
        } while (changed);


        // 5.5) Identify variables that are *produced* by crypto/opaque operations,
        // so they should be treated as "Observed Crypto Objects" (e.g., c = Enc(...))
        Set<String> cryptoVars = new HashSet<>();
        for (MessageSendNode msg : proto.getMessages()) {
            if (msg.getBody() instanceof AssignNode a) {
                if (isCryptoExpr(a.getValue())) {
                    cryptoVars.add(a.getTarget().getName());
                }
            }
        }


        // 6) Build pretty, categorized output (clean report style)
        StringBuilder sb = new StringBuilder();
        sb.append("==================================================\n");
        sb.append("PROTOCOL KNOWLEDGE ANALYSIS\n");
        sb.append("==================================================\n\n");

        sb.append("Principals:\n");
        for (IdentifierNode id : proto.getRoles().getRoles()) {
            sb.append("  - ").append(id.getName()).append("\n");
        }
        sb.append("  - ").append(ADVERSARY).append(" (Passive Eavesdropper)\n\n");

        // We'll collect what the adversary learned for the final verdict here:
        Set<String> advSecretsForVerdict   = new LinkedHashSet<>();
        Set<String> advPlaintextForVerdict = new LinkedHashSet<>();

        // Print all non-adversary principals first, then adversary last
        List<String> ordered = new ArrayList<>(knows.keySet());
        ordered.remove(ADVERSARY);
        ordered.add(ADVERSARY);

        for (String principal : ordered) {

            sb.append("--------------------------------------------------\n");
            if (principal.equals(ADVERSARY)) {
                sb.append("Adversary (Passive Eavesdropper)\n");
            } else {
                sb.append(principal).append("\n");
            }
            sb.append("--------------------------------------------------\n");

            // Gather all terms this principal knows/sees
            Set<String> all = new LinkedHashSet<>();
            all.addAll(knows.get(principal));
            // NOTE: we intentionally do NOT dump encryptTerms directly, because it causes redundancy.
            // The assigned variable name (like "c") is what we want to show users.

            // Categorize
            Set<String> secrets   = new LinkedHashSet<>();
            Set<String> plaintext = new LinkedHashSet<>();
            Set<String> observed  = new LinkedHashSet<>();

            for (String term : all) {

                // Keys / secrets
                if (isSecretLike(term, secretKeys)) {
                    secrets.add(term);
                    continue;
                }

                // Anything structured is a crypto object (Enc(...), Hash(...), etc.)
                if (isStructuredTerm(term)) {
                    observed.add(term);
                    continue;
                }

                if (cryptoVars.stream().anyMatch(v -> v.equalsIgnoreCase(term))) {
                    observed.add(term);
                    continue;
                }


                // Otherwise it's plaintext-like data (M1, N_A, etc.)
                if (isPlaintextLike(term, keyKinds, cryptoVars)) {
                    plaintext.add(term);
                } else {
                    observed.add(term);
                }
            }

            // Adversary output focuses on what they observe + what they learn
            if (principal.equals(ADVERSARY)) {
                sb.append("Observed Messages / Objects:\n");
                if (observed.isEmpty()) sb.append("  (none)\n");
                else for (String t : observed) sb.append("  - ").append(t).append("\n");

                sb.append("\nSecrets Learned:\n");
                if (secrets.isEmpty()) sb.append("  (none)\n");
                else for (String t : secrets) sb.append("  - ").append(t).append("\n");

                sb.append("\nPlaintext Learned:\n");
                if (plaintext.isEmpty()) sb.append("  (none)\n");
                else for (String t : plaintext) sb.append("  - ").append(t).append("\n");

                // ✅ THIS IS THE FIX: feed the verdict from the exact buckets printed above
                advSecretsForVerdict.addAll(secrets);
                advPlaintextForVerdict.addAll(plaintext);

                sb.append("\n");
                continue;
            }

            // Normal principal output
            sb.append("Secrets Known:\n");
            if (secrets.isEmpty()) sb.append("  (none)\n");
            else for (String t : secrets) sb.append("  - ").append(t).append("\n");

            sb.append("\nPlaintext Data:\n");
            if (plaintext.isEmpty()) sb.append("  (none)\n");
            else for (String t : plaintext) sb.append("  - ").append(t).append("\n");

            sb.append("\nObserved Crypto Objects:\n");
            if (observed.isEmpty()) sb.append("  (none)\n");
            else for (String t : observed) sb.append("  - ").append(t).append("\n");

            sb.append("\n");
        }

        // 7) Verdict / catastrophic leak summary
        Set<String> catastrophic = new LinkedHashSet<>();
        catastrophic.addAll(advSecretsForVerdict);
        catastrophic.addAll(advPlaintextForVerdict);

        // Only keep “catastrophic-looking” items
        catastrophic.removeIf(t ->
            !(t.startsWith("K_") || t.startsWith("M") || t.startsWith("sk"))
        );

        sb.append("--------------------------------------------------\n");
        sb.append("SECURITY VERDICT\n");
        sb.append("--------------------------------------------------\n");

        if (!catastrophic.isEmpty()) {
            sb.append("Potentially catastrophic leak detected.\n");
            sb.append("Adversary learned:\n");
            for (String t : catastrophic) sb.append("  - ").append(t).append("\n");
        } else {
            sb.append("No catastrophic leaks detected under this simple model.\n");
        }

        sb.append("\n==================================================\n");
        return sb.toString();


    }

    private static boolean learnFromDecryptedPlaintext(SyntaxNode node, Set<String> out) {
        boolean changed = false;

        if (node instanceof IdentifierNode id) {
            return out.add(id.getName());
        }

        if (node instanceof ConcatNode cat) {
            changed |= learnFromDecryptedPlaintext(cat.getLeft(), out);
            changed |= learnFromDecryptedPlaintext(cat.getRight(), out);
            return changed;
        }

        // For now, keep other structured plaintext as a single observed blob.
        // (You can expand later if you want.)
        return out.add(node.label());
    }



    /**
     * Heuristic: treat anything with parentheses or "||" as a structured term
     * (ciphertext, MAC, signature, hash, concat, etc.)
     */
    private static boolean isStructuredTerm(String term) {
        return term.contains("(") || term.contains("||");
    }

    /**
     * Collect identifiers that a sender must know in order to BUILD the message.
     * Unlike collectTerms, this ignores visibility rules and recurses into
     * the internals of crypto/concat expressions.
     */
    private static void collectAuthorIds(SyntaxNode node, Set<String> out) {
        if (node instanceof IdentifierNode id) {
            out.add(id.getName());
        } else if (node instanceof EncryptExprNode enc) {
            collectAuthorIds(enc.getKey(), out);
            collectAuthorIds(enc.getMessage(), out);
        } else if (node instanceof ConcatNode cat) {
            collectAuthorIds(cat.getLeft(), out);
            collectAuthorIds(cat.getRight(), out);
        } else if (node instanceof MacExprNode mac) {
            collectAuthorIds(mac.getKey(), out);
            collectAuthorIds(mac.getMessage(), out);
        } else if (node instanceof HashExprNode h) {
            collectAuthorIds(h.getInner(), out);
        } else if (node instanceof SignExprNode s) {
            collectAuthorIds(s.getSigningKey(), out);
            collectAuthorIds(s.getMessage(), out);
        } else if (node instanceof VerifyExprNode v) {
            collectAuthorIds(v.getPublicKey(), out);
            collectAuthorIds(v.getMessage(), out);
            collectAuthorIds(v.getSignature(), out);
        } else if (node instanceof AssignNode a) {
            // The sender obviously knows the variable they assign to and
            // all identifiers used in the assigned expression.
            collectAuthorIds(a.getTarget(), out);
            collectAuthorIds(a.getValue(), out);
        }
        // For other node types, nothing to do
    }

    /**
     * Treat as "bare identifier" only simple symbols like K_AB, M_1, N_A, c, ack.
     * We exclude anything with non [A-Za-z0-9_] characters, and also the internal
     * "Concat" label which comes from expression labels, not from user-level ids.
     */
    private static boolean isBareIdentifier(String term) {
        if ("Concat".equals(term)) {
            return false; // internal label for concatenations; not a user-visible atom
        }
        if (term.isEmpty()) {
            return false;
        }
        for (int i = 0; i < term.length(); i++) {
            char c = term.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '_')) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSecretLike(String term, Set<String> secretKeys) {
        return secretKeys.contains(term);
    }

    private static boolean isPlaintextLike(String term,
                                       Map<String, KeyKind> keyKinds,
                                       Set<String> cryptoVars) {
    // plaintext = a bare identifier that is NOT a key and NOT a crypto variable
    return isBareIdentifier(term) && !keyKinds.containsKey(term) && !cryptoVars.contains(term);
}


    /**
     * Decryption rule guard:
     * - Knowing a PUBLIC key used in Enc(pkX, ...) does NOT enable decryption.
     * - Only SHARED keys (K_*) and PRIVATE keys (sk*) should enable decryption.
     */
    private static boolean canDecrypt(Set<String> terms, String keyName, Map<String, KeyKind> keyKinds) {
        if (!terms.contains(keyName)) return false;

        // If we have keyKinds available, this is the cleanest:
        KeyKind kind = keyKinds.get(keyName);
        if (kind != null) {
            return kind == KeyKind.SHARED || kind == KeyKind.PRIVATE;
        }

        // Fallback heuristic if keyKinds doesn't contain it
        return keyName.startsWith("K_") || keyName.startsWith("sk");
    }

    private static boolean isCryptoExpr(SyntaxNode node) {
        return node instanceof EncryptExprNode
            || node instanceof MacExprNode
            || node instanceof HashExprNode
            || node instanceof SignExprNode
            || node instanceof VerifyExprNode
            || node instanceof ConcatNode;
    }

    /**
     * Map a public key name to its corresponding private key name.
     *
     * This analyzer assumes the naming convention:
     *   pkX -> skX
     *
     * This is a modeling assumption, not a cryptographic derivation.
     */
    private static String matchingPrivateKeyName(String pkName) {
        if (pkName.startsWith("pk") && pkName.length() > 2) {
            return "sk" + pkName.substring(2);
        }
        return null;
    }
}

