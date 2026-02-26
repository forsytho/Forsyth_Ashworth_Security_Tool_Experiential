package com.dynamicduo.proto.render;

import com.dynamicduo.proto.ast.*;

import java.util.List;
import java.util.stream.Collectors;

/**
 * LatexRenderer
 *
 * Converts the protocol AST into copy-pasteable LaTeX 
 *
 * Output is intended to be pasted into homework/notes, e.g. inside:
 *   \[
 *     ... output ...
 *   \]
 */
public final class LatexRenderer {

    private LatexRenderer() {}

        // Export the full protocol as a LaTeX block (aligned)
        public static String protocolToLatex(ProtocolNode proto) {
        StringBuilder sb = new StringBuilder();

        // Use aligned so arrows line up nicely
        sb.append("\\begin{aligned}\n");

        List<MessageSendNode> msgs = proto.getMessages();
        for (int i = 0; i < msgs.size(); i++) {
            MessageSendNode m = msgs.get(i);

            String line = messageToLatex(m);

            // LaTeX newline between rows. Avoid trailing \\ on last line if you care.
            sb.append("  ").append(line);
            if (i < msgs.size() - 1) sb.append(" \\\\");
            sb.append("\n");
        }

        sb.append("\\end{aligned}");
        return sb.toString();
    }

    /** Export a single message line as LaTeX. */
    public static String messageToLatex(MessageSendNode m) {
        String sender = identToLatex(m.getSender().getName());
        String recv   = identToLatex(m.getReceiver().getName());
        String body   = exprToLatex(m.getBody());

        // Alice -> Bob : body
        return sender + " \\rightarrow " + recv + " : " + body;
    }

    /** Convert a syntax node (expression/stmt) into LaTeX math. */
    public static String exprToLatex(SyntaxNode node) {
        if (node == null) return "";

        if (node instanceof AssignNode a) {
            return identToLatex(a.getTarget().getName()) + " = " + exprToLatex(a.getValue());
        }

        if (node instanceof IdentifierNode id) {
            return identToLatex(id.getName());
        }

        if (node instanceof EncryptExprNode e) {
            return "\\mathsf{Enc}\\big(" +
                    identToLatex(e.getKey().getName()) + ", " +
                    exprToLatex(e.getMessage()) +
                    "\\big)";
        }

        if (node instanceof MacExprNode m) {
            return "\\mathsf{Mac}\\big(" +
                    identToLatex(m.getKey().getName()) + ", " +
                    exprToLatex(m.getMessage()) +
                    "\\big)";
        }

        if (node instanceof HashExprNode h) {
            return "\\mathsf{H}\\big(" + exprToLatex(h.getInner()) + "\\big)";
        }

        if (node instanceof SignExprNode s) {
            return "\\mathsf{Sign}\\big(" +
                    identToLatex(s.getSigningKey().getName()) + ", " +
                    exprToLatex(s.getMessage()) +
                    "\\big)";
        }

        if (node instanceof VerifyExprNode v) {
            return "\\mathsf{Verify}\\big(" +
                    identToLatex(v.getPublicKey().getName()) + ", " +
                    exprToLatex(v.getMessage()) + ", " +
                    exprToLatex(v.getSignature()) +
                    "\\big)";
        }

        if (node instanceof ConcatNode c) {
            // Use \parallel for concatenation
            return exprToLatex(c.getLeft()) + " \\parallel " + exprToLatex(c.getRight());
        }

        // Fallback (should be rare if you cover all node types)
        return escapeLatex(node.label());
    }

    /**
     * Convert an identifier into LaTeX-safe text.
     * Minimal rule: escape characters that break LaTeX.
     *
     * NOTE: We do NOT force k_AB -> k_{AB} here, because naming is flexible.
     * If we later want fancy subscripts, add a separate "style" option.
     */
    private static String identToLatex(String id) {
        return escapeLatex(id);
    }

    /** Escape common LaTeX special characters in identifiers/labels. */
    private static String escapeLatex(String s) {
        if (s == null) return "";
        // Order matters: backslash first
        return s
                .replace("\\", "\\textbackslash{}")
                .replace("{", "\\{")
                .replace("}", "\\}")
                .replace("_", "\\_")
                .replace("#", "\\#")
                .replace("$", "\\$")
                .replace("%", "\\%")
                .replace("&", "\\&")
                .replace("^", "\\^{}")
                .replace("~", "\\~{}");
    }
}
