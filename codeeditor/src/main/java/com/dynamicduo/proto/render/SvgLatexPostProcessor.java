package com.dynamicduo.proto.render;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SvgLatexPostProcessor {

    private SvgLatexPostProcessor() {}

    /**
     * Replaces <text ...>__LATEX_i__</text> with a positioned <g> containing LaTeX paths.
     * Works with SVGSalamander because we no longer nest <g> inside <text>.
     */
    public static String replacePlaceholders(String svg,
                                             Map<String, String> placeholderToLatex,
                                             float fontSize) {

        for (Map.Entry<String, String> e : placeholderToLatex.entrySet()) {
            String placeholder = e.getKey();
            String latex = e.getValue();

            // Match <text ... x=".." y=".."...> __LATEX_i__ </text>
            // We capture:
            // 1) the whole <text ...> opening tag attributes
            // 2) x
            // 3) y
            Pattern p = Pattern.compile(
                    "<text([^>]*?)\\sx=\"([^\"]+)\"\\sy=\"([^\"]+)\"([^>]*)>\\s*"
                            + Pattern.quote(placeholder)
                            + "\\s*</text>",
                    Pattern.CASE_INSENSITIVE
            );

            Matcher m = p.matcher(svg);
            StringBuffer sb = new StringBuffer();

            while (m.find()) {
                String x = m.group(2);
                String y = m.group(3);

                // Convert LaTeX -> SVG paths/group
                String latexGroup = LatexSvg.toSvgGroup(latex, fontSize);

                // Position it where the text was.
                // Baseline tweak: translate up a bit so it sits like text.
                String replacement =
                        "<g transform=\"translate(" + x + "," + y + ") translate(0,-6)\">"
                                + latexGroup
                                + "</g>";

                m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }

            m.appendTail(sb);
            svg = sb.toString();
        }

        return svg;
    }
}
