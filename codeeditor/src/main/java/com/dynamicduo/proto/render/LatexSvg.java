package com.dynamicduo.proto.render;

import org.scilab.forge.jlatexmath.TeXFormula;
import org.scilab.forge.jlatexmath.TeXIcon;

import org.apache.batik.dom.GenericDOMImplementation;
import org.apache.batik.svggen.SVGGraphics2D;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;

import javax.swing.*;
import java.awt.*;
import java.io.StringWriter;

public final class LatexSvg {
    private LatexSvg() {}

    /** Returns an SVG fragment (<g>...</g>) with vector paths for LaTeX. */
    public static String toSvgGroup(String latex, float fontSize) {
        try {
            TeXFormula formula = new TeXFormula(latex);
            TeXIcon icon = formula.createTeXIcon(TeXFormula.SERIF, fontSize);

            DOMImplementation impl = GenericDOMImplementation.getDOMImplementation();
            String svgNS = "http://www.w3.org/2000/svg";
            Document doc = impl.createDocument(svgNS, "svg", null);

            SVGGraphics2D g2 = new SVGGraphics2D(doc);
            g2.setSVGCanvasSize(new Dimension(icon.getIconWidth(), icon.getIconHeight()));

            icon.paintIcon(new JLabel(), g2, 0, 0);

            StringWriter sw = new StringWriter();
            g2.stream(sw, true);

            String full = sw.toString();
            int start = full.indexOf(">", full.indexOf("<svg"));
            int end = full.lastIndexOf("</svg>");
            String inner = (start >= 0 && end > start) ? full.substring(start + 1, end).trim() : "";

            return "<g class=\"latex\">" + inner + "</g>";
        } catch (Exception e) {
            // fallback: plain text inside a <text>
            String safe = latex.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
            return "<g class=\"latex-fallback\"><text>" + safe + "</text></g>";
        }
    }
}
