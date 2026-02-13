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
import com.dynamicduo.proto.render.SVG;

import guru.nidi.graphviz.model.*;
import static guru.nidi.graphviz.model.Factory.*;
import guru.nidi.graphviz.attribute.*;
import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;

import java.io.File;
import java.util.List;
import java.util.stream.Collectors;

/**
 * SequenceDiagramFromAst
 *
 * Bridges our Protocol AST into the existing SVG.java two-party sequence
 * diagram
 * 
 *
 * Assumptions:
 * - The protocol declares exactly TWO roles.
 * - Each message is represented as a MessageSendNode with
 * sender, receiver, and a body expression.
 *
 * Output:
 * - An SVG file with Alice/Bob style vertical lifelines and
 * horizontal arrows for each message.
 */
public final class SequenceDiagramFromAst {

    private SequenceDiagramFromAst() {
    }

    /**
     * Render a two-party sequence diagram using your partner's SVG.java.
     *
     * @param proto  Root AST (ProtocolNode)
     * @param outSvg Output SVG path, e.g. "pretty_protocol.svg"
     */
    public static String renderTwoParty(ProtocolNode proto) throws Exception {
        List<String> roles = proto.getRoles().getRoles().stream()
                .map(IdentifierNode::getName)
                .collect(Collectors.toList());

        if (roles.size() != 2) {
            throw new IllegalArgumentException(
                    "Two-party renderer requires exactly 2 roles, found: " + roles.size());
        }

        String p1 = roles.get(0);
        String p2 = roles.get(1);

        List<MessageSendNode> msgs = proto.getMessages();
        int numNodes = msgs.size() + 1;

        String[] messages = new String[msgs.size()];
        String[] passer = new String[msgs.size()];

        // Map placeholder -> latex
        java.util.Map<String, String> latexMap = new java.util.LinkedHashMap<>();

        for (int i = 0; i < msgs.size(); i++) {
            MessageSendNode m = msgs.get(i);

            String placeholder = "__LATEX_" + i + "__";
            messages[i] = placeholder;                 // what Graphviz will draw
            latexMap.put(placeholder, latexFor(m.getBody())); // what we want instead

            passer[i] = m.getSender().getName();
        }

        SVG svgBuilder = new SVG(numNodes, p1, p2, messages, passer);

        String outSvg = Graphviz.fromGraph(svgBuilder.getGraph())
                .render(Format.SVG)
                .toString();

        // Post-process SVG: replace each placeholder text with LaTeX paths
        outSvg = SvgLatexPostProcessor.replacePlaceholders(outSvg, latexMap, 16f);

        return outSvg;
    }


    // === label helper: reuse our encryption labeling logic ===

    private static String latexFor(SyntaxNode body) {
        if (body instanceof AssignNode a) {
            return a.getTarget().getName() + " = " + latexFor(a.getValue());
        }
        if (body instanceof EncryptExprNode e) {
            return "\\mathrm{Enc}\\left(" + e.getKey().getName() + ",\\," + latexFor(e.getMessage()) + "\\right)";
        }
        if (body instanceof MacExprNode m) {
            return "\\mathrm{Mac}\\left(" + m.getKey().getName() + ",\\," + latexFor(m.getMessage()) + "\\right)";
        }
        if (body instanceof SignExprNode s) {
            return "\\mathrm{Sign}\\left(" + s.getSigningKey().getName() + ",\\," + latexFor(s.getMessage()) + "\\right)";
        }
        if (body instanceof VerifyExprNode v) {
            return "\\mathrm{Verify}\\left(" + v.getPublicKey().getName() + ",\\,"
                    + latexFor(v.getMessage()) + ",\\," + latexFor(v.getSignature()) + "\\right)";
        }
        if (body instanceof HashExprNode h) {
            return "H\\left(" + latexFor(h.getInner()) + "\\right)";
        }
        if (body instanceof ConcatNode c) {
            return latexFor(c.getLeft()) + " \\parallel " + latexFor(c.getRight());
        }
        if (body instanceof IdentifierNode id) {
            return id.getName();
        }
        return body.label(); // fallback
    }
}
