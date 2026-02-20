package com.dynamicduo.proto.render;

import org.scilab.forge.jlatexmath.TeXFormula;
import org.scilab.forge.jlatexmath.TeXIcon;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Base64;

import javax.imageio.ImageIO;

/**
 * LatexSvg
 *
 * Renders a LaTeX math string to a PNG data URI.
 */
public final class LatexSvg {

    private LatexSvg() {}

    public static final class PngFragment {
        public final String dataUri;
        public final int width;   // display width in SVG pixels
        public final int height;  // display height in SVG pixels

        public PngFragment(String dataUri, int width, int height) {
            this.dataUri = dataUri;
            this.width = width;
            this.height = height;
        }
    }

    /**
     * Render LaTeX to PNG data URI.
     *
     * @param latex    LaTeX math content (no $ needed)
     * @param fontSize base font size (e.g. 18f)
     * @param scale    oversampling factor (e.g. 2f or 3f). Render bigger, then display smaller.
     */
    public static PngFragment toPngDataUri(String latex, float fontSize, float scale) {
        if (latex == null) latex = "";
        if (scale <= 0f) scale = 1f;

        try {
            // Build icon at higher resolution
            TeXFormula formula = new TeXFormula(latex);
            TeXIcon icon = formula.createTeXIcon(TeXFormula.SERIF, fontSize * scale);

            int w = Math.max(1, icon.getIconWidth());
            int h = Math.max(1, icon.getIconHeight());

            BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = img.createGraphics();

            // High quality rendering hints
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
            g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);

            // Transparent background
            g.setComposite(AlphaComposite.Src);
            g.setColor(new Color(0, 0, 0, 0));
            g.fillRect(0, 0, w, h);

            // Draw LaTeX in black
            g.setColor(Color.BLACK);
            icon.paintIcon(new JLabel(), g, 0, 0);
            g.dispose();

            // Encode to PNG base64
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(img, "png", baos);
            baos.flush();

            String base64 = Base64.getEncoder().encodeToString(baos.toByteArray());
            String uri = "data:image/png;base64," + base64;

            // IMPORTANT: display size is scaled back down
            int displayW = Math.max(1, Math.round(w / scale));
            int displayH = Math.max(1, Math.round(h / scale));

            return new PngFragment(uri, displayW, displayH);

        } catch (Exception e) {
            // Fallback: render an empty 1x1 transparent pixel
            String uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=";
            return new PngFragment(uri, 1, 1);
        }
    }
}
