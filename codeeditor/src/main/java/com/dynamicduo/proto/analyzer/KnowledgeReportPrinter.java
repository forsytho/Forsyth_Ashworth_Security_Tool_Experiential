package com.dynamicduo.proto.analyzer;

import com.dynamicduo.proto.ast.IdentifierNode;
import com.dynamicduo.proto.ast.ProtocolNode;

import java.util.*;

public final class KnowledgeReportPrinter {
    private KnowledgeReportPrinter() {}

    private static final String ADVERSARY = "Adversary";

    public static String toStringReport(ProtocolNode proto, KnowledgeResult result) {
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
        List<String> ordered = new ArrayList<>(result.knows().keySet());
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
            all.addAll(result.knows().getOrDefault(principal, Set.of()));

            // Categorize
            Set<String> secrets   = new LinkedHashSet<>();
            Set<String> plaintext = new LinkedHashSet<>();
            Set<String> observed  = new LinkedHashSet<>();

            for (String term : all) {

                // Keys / secrets
                if (result.secretKeys().contains(term)) {
                    secrets.add(term);
                    continue;
                }

                // Anything structured is a crypto object (Enc(...), Hash(...), etc.)
                if (isStructuredTerm(term)) {
                    observed.add(term);
                    continue;
                }

                // Vars that represent crypto results (c = Enc(...))
                if (result.cryptoVars().contains(term)) {
                    observed.add(term);
                    continue;
                }

                // Otherwise it's plaintext-like data (m, nonceA, ...)
                if (isPlaintextLike(term, result.keyKinds(), result.cryptoVars())) {
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

        // Verdict / catastrophic leak summary (same as before)
        Set<String> catastrophic = new LinkedHashSet<>();
        catastrophic.addAll(advSecretsForVerdict);
        catastrophic.addAll(advPlaintextForVerdict);

        catastrophic.removeIf(t ->
                !(t.startsWith("K_") || t.startsWith("M") || t.startsWith("sk"))
        );

        sb.append("--------------------------------------------------\n");
        sb.append("MESSAGE FRESHNESS REPORT (Global Nonce Usage)\n");
        sb.append("--------------------------------------------------\n");

        List<KnowledgeAnalyzer.FreshnessResult> freshness = result.freshnessResults();
        if (freshness == null || freshness.isEmpty()) {
            sb.append("(no messages)\n\n");
        } else {
            for (KnowledgeAnalyzer.FreshnessResult fr : freshness) {

                sb.append(fr.index()).append(". ")
                    .append(fr.sender()).append(" -> ").append(fr.receiver()).append(": ")
                    .append(fr.messageLabel()).append("\n");

                if (fr.status() == KnowledgeAnalyzer.FreshnessStatus.FRESH) {
                    sb.append("   Fresh (new nonce: ").append(fr.newNonces()).append(")\n");
                } else {
                    if (fr.reason() == KnowledgeAnalyzer.FreshnessReason.NO_NONCE) {
                        sb.append("   Replayable (no nonce)\n");
                    } else {
                        sb.append("   Replay (nonce reused: ").append(fr.reusedNonces()).append(")\n");
                    }
                }
                sb.append("\n");
            }
        }


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

    // --- These helpers used to be in KnowledgeAnalyzer; printer can own them now. ---

    private static boolean isStructuredTerm(String term) {
        return term.contains("(") || term.contains("||");
    }

    private static boolean isBareIdentifier(String term) {
        if (term == null || term.isEmpty()) return false;
        if ("Concat".equals(term)) return false;
        for (int i = 0; i < term.length(); i++) {
            char c = term.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '_')) return false;
        }
        return true;
    }

    private static boolean isPlaintextLike(
            String term,
            Map<String, com.dynamicduo.proto.ast.KeyKind> keyKinds,
            Set<String> cryptoVars
    ) {
        return isBareIdentifier(term) && !keyKinds.containsKey(term) && !cryptoVars.contains(term);
    }
}
