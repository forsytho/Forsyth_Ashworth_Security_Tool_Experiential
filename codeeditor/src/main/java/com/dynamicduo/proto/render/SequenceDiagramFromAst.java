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
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*
*/

package com.dynamicduo.proto.render;

import com.dynamicduo.proto.ast.*;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;

import java.util.List;
import java.util.stream.Collectors;

/**
 * SequenceDiagramFromAst
 *
 * Bridges our Protocol AST into the existing SVG.java two-party sequence diagram.
 *
 * Assumptions:
 * - The protocol declares exactly TWO roles.
 * - Each message is represented as a MessageSendNode with sender, receiver, and a body expression.
 *
 * Output:
 * - An SVG (string) with Alice/Bob style vertical lifelines and horizontal arrows for each message.
 *
 * NOTE:
 * - We use LaTeX placeholders (__LATEX_i__) and then post-process the SVG to replace them with LaTeX
 *   rendered fragments (PNG-in-SVG recommended for SVGSalamander compatibility).
 */
public final class SequenceDiagramFromAst {

    private SequenceDiagramFromAst() {}

    public static String renderTwoParty(ProtocolNode proto) throws Exception {
        // 1) Extract roles in declaration order
        List<String> roles = proto.getRoles().getRoles().stream()
                .map(IdentifierNode::getName)
                .collect(Collectors.toList());

        if (roles.size() != 2) {
            throw new IllegalArgumentException(
                    "Two-party renderer requires exactly 2 roles, found: " + roles.size());
        }

        String p1 = roles.get(0);
        String p2 = roles.get(1);

        // 2) Messages define the rows
        List<MessageSendNode> msgs = proto.getMessages();
        int numNodes = msgs.size() + 1; // lifeline points = messages + 1

        String[] messages = new String[msgs.size()];
        String[] passer = new String[msgs.size()];

        // Map placeholder -> latex
        java.util.Map<String, String> latexMap = new java.util.LinkedHashMap<>();

        for (int i = 0; i < msgs.size(); i++) {
            MessageSendNode m = msgs.get(i);

            String placeholder = "__LATEX_" + i + "__";
            messages[i] = placeholder; // what Graphviz will draw
            latexMap.put(placeholder, latexFor(m.getBody())); // what we want instead

            passer[i] = m.getSender().getName(); // who sends this message
        }

        // 3) Build the graph using SVG helper
        SVG svgBuilder = new SVG(numNodes, p1, p2, messages, passer);

        // 4) Render graph to SVG
        String outSvg = Graphviz.fromGraph(svgBuilder.getGraph())
                .render(Format.SVG)
                .toString();

        // 5) Post-process SVG: replace each placeholder with LaTeX
        // For PNG-in-SVG replacement, bump font a bit for readability.
        outSvg = SvgLatexPostProcessor.replacePlaceholders(outSvg, latexMap, 18f);

        System.out.println("Has placeholders after replace? " + outSvg.contains("__LATEX_"));
        System.out.println("Has embedded PNG images? " + outSvg.contains("data:image/png;base64,"));


        return outSvg;
    }

    // =========================
    // LaTeX formatting helpers
    // =========================

    /**
     * Escape identifiers that might contain characters LaTeX treats specially.
     * This prevents crashes / missing labels when users name keys like K_ab.
     */
    private static String texId(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\textbackslash{}")
                .replace("_", "\\_")
                .replace("{", "\\{")
                .replace("}", "\\}")
                .replace("#", "\\#")
                .replace("$", "\\$")
                .replace("%", "\\%")
                .replace("&", "\\&");
    }

    /**
     * Convert an AST expression into a LaTeX string.
     * IMPORTANT: We run identifiers through texId(...) so underscores etc. don't break rendering.
     */
    private static String latexFor(SyntaxNode body) {
        if (body instanceof AssignNode a) {
            return texId(a.getTarget().getName()) + " = " + latexFor(a.getValue());
        }
        if (body instanceof EncryptExprNode e) {
            return "\\mathrm{Enc}\\left(" + texId(e.getKey().getName()) + ",\\," + latexFor(e.getMessage()) + "\\right)";
        }
        if (body instanceof MacExprNode m) {
            return "\\mathrm{Mac}\\left(" + texId(m.getKey().getName()) + ",\\," + latexFor(m.getMessage()) + "\\right)";
        }
        if (body instanceof SignExprNode s) {
            return "\\mathrm{Sign}\\left(" + texId(s.getSigningKey().getName()) + ",\\," + latexFor(s.getMessage()) + "\\right)";
        }
        if (body instanceof VerifyExprNode v) {
            return "\\mathrm{Verify}\\left(" + texId(v.getPublicKey().getName()) + ",\\,"
                    + latexFor(v.getMessage()) + ",\\," + latexFor(v.getSignature()) + "\\right)";
        }
        if (body instanceof HashExprNode h) {
            return "H\\left(" + latexFor(h.getInner()) + "\\right)";
        }
        if (body instanceof ConcatNode c) {
            // Looks like "||" in math typesetting (often nicer than \parallel for students)
            return latexFor(c.getLeft()) + " \\;\\Vert\\; " + latexFor(c.getRight());
        }
        if (body instanceof IdentifierNode id) {
            return texId(id.getName());
        }

        // Fallback
        return texId(body.label());
    }
}
