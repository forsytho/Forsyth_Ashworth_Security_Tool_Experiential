package com.dynamicduo.proto.render;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SvgLatexPostProcessor {

    private SvgLatexPostProcessor() {}

    public static String replacePlaceholders(
            String svg,
            Map<String, String> placeholderToLatex,
            float fontSize
    ) {
        for (Map.Entry<String, String> entry : placeholderToLatex.entrySet()) {
            svg = replaceOne(svg, entry.getKey(), entry.getValue(), fontSize);
        }
        return svg;
    }

    private static String replaceOne(String svg, String placeholder, String latex, float fontSize) {

        Pattern p = Pattern.compile(
                "<text(?<attrs>[^>]*)\\sx=\"(?<x>[^\"]+)\"\\sy=\"(?<y>[^\"]+)\"(?<attrs2>[^>]*)>"
                        + "(?<inner>[\\s\\S]*?)"
                        + "</text>",
                Pattern.CASE_INSENSITIVE
        );

        Matcher m = p.matcher(svg);
        StringBuffer out = new StringBuffer();

        while (m.find()) {
            String inner = m.group("inner");
            if (inner == null || !inner.contains(placeholder)) {
                m.appendReplacement(out, Matcher.quoteReplacement(m.group(0)));
                continue;
            }

            String xStr = m.group("x");
            String yStr = m.group("y");

            double x = parseDoubleSafe(xStr);
            double y = parseDoubleSafe(yStr);

            LatexSvg.PngFragment frag = LatexSvg.toPngDataUri(latex, fontSize, 3f);

            double imgX = x - (frag.width / 2.0);
            double imgY = y - (frag.height * 0.75);

           String replacement =
                   // <text ... x="..." y="...">
                "<image xmlns=\"http://www.w3.org/2000/svg\" " +
                "xmlns:xlink=\"http://www.w3.org/1999/xlink\" " +
                "x=\"" + imgX + "\" " +
                "y=\"" + imgY + "\" " +
                "width=\"" + frag.width + "\" " +
                "height=\"" + frag.height + "\" " +
                "xlink:href=\"" + frag.dataUri + "\" " +
                "href=\"" + frag.dataUri + "\"/>";

            m.appendReplacement(out, Matcher.quoteReplacement(replacement));
        }

        m.appendTail(out);
        return out.toString();
    }

    private static double parseDoubleSafe(String s) {
        try { return Double.parseDouble(s); }
        catch (Exception e) { return 0.0; }
    }
}
