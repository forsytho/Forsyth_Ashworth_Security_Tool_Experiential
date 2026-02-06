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

package com.dynamicduo;

import com.dynamicduo.proto.lexer.Lexer;
import com.dynamicduo.proto.parser.ProtocolParser;
import com.dynamicduo.proto.parser.ParseException;
import com.dynamicduo.proto.ast.ProtocolNode;
import com.dynamicduo.proto.render.SequenceDiagramFromAst;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.prefs.Preferences;

import org.fife.ui.rsyntaxtextarea.*;
import org.fife.ui.rtextarea.*;

import com.kitfox.svg.SVGUniverse;
import com.kitfox.svg.app.beans.SVGIcon;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

import com.dynamicduo.proto.analyzer.KnowledgeAnalyzer;
import com.dynamicduo.proto.codegen.JavaCodeGenerator;



public class GUI extends JFrame implements KeyListener {

    private JTextArea headingArea, analysisArea, errorArea;
    private JScrollPane headingScroll, svgScroll, analysisScroll, errorScroll;

    private JPanel messageHeaderPanel;

    private RSyntaxTextArea codeArea;
    private RTextScrollPane codeScroll;

    private String currentMode = "message";
    private final HashMap<String, String> modeBuffers = new HashMap<>();
    private JSplitPane splitPane, splitPane2, splitPane3, splitPane4;

    private JButton messageBtn, svgBtn, javaBtn, analysisBtn;
    private JButton uploadBtn, runBtn, saveBtn, displayBtn;
    private JButton syntaxBtn;

    private String analysisStr, svgStr;

    private ProtocolNode lastProtocol;

    private boolean executed = false, dark = false;
    private JLabel label = new JLabel();
    private double zoomFactor = 1.0;


    public GUI() {
        setTitle("Secure Protocol Editor");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 600);
        setLocationRelativeTo(null);
        addKeyListener(this);
        setFocusable(true);

        setLayout(new BorderLayout());

        // creates top panel to place all buttons on
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridLayout(1, 2));

        // Creates Nav panel to allow for change between modes
        JPanel navPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        messageBtn = new JButton("Editor");
        svgBtn = new JButton("SVG");
        javaBtn = new JButton("Java Code");
        analysisBtn = new JButton("Analysis");
        syntaxBtn = new JButton("Syntax");

        // set button size and fonts
        messageBtn.setPreferredSize(new Dimension(105, 35));
        messageBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        svgBtn.setPreferredSize(new Dimension(80, 35));
        svgBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        javaBtn.setPreferredSize(new Dimension(120, 35));
        javaBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        analysisBtn.setPreferredSize(new Dimension(105, 35));
        analysisBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        syntaxBtn.setPreferredSize(new Dimension(100, 35));
        syntaxBtn.setFont(new Font("Verdana", Font.BOLD, 14));

        // add to navigation panel
        navPanel.add(messageBtn);
        navPanel.add(svgBtn);
        navPanel.add(javaBtn);
        navPanel.add(analysisBtn);

        topPanel.add(navPanel);

        // Creates Button panel to place function buttons on
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        

        // Assigning buttons
        runBtn = new JButton("Run");
        saveBtn = new JButton("Save As");
        uploadBtn = new JButton("Upload");
        displayBtn = new JButton("Dark Mode");

        // set button size and fonts
        runBtn.setPreferredSize(new Dimension(80, 35));
        runBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        saveBtn.setPreferredSize(new Dimension(80, 35));
        saveBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        uploadBtn.setPreferredSize(new Dimension(100, 35));
        uploadBtn.setFont(new Font("Verdana", Font.BOLD, 14));
        displayBtn.setPreferredSize(new Dimension(125, 35));
        displayBtn.setFont(new Font("Verdana", Font.BOLD, 14));

        // add to button panel
        buttonPanel.add(runBtn);
        buttonPanel.add(saveBtn);
        buttonPanel.add(uploadBtn);
        buttonPanel.add(displayBtn);

        topPanel.add(buttonPanel);

        add(topPanel, BorderLayout.NORTH);

        // Set Up Header Area
        headingArea = new JTextArea(3, 100);
        headingArea.setFont(new Font("Consolas", Font.BOLD, 14));
        headingArea.setEditable(false);
        headingArea.setBackground(new Color(230, 230, 230));

        headingScroll = new JScrollPane(headingArea);
        headingScroll.getVerticalScrollBar().putClientProperty("JScrollBar.fastWheelScrolling", true);

        // Syntax button (only shown in Message mode header)
        syntaxBtn = new JButton("Syntax");
        syntaxBtn.setPreferredSize(new Dimension(110, 35));
        syntaxBtn.setFont(new Font("Verdana", Font.BOLD, 13));

        // Panel that sits INSIDE the "Message Mode" header box
        messageHeaderPanel = new JPanel(new BorderLayout());
        messageHeaderPanel.add(headingScroll, BorderLayout.CENTER);

        JPanel syntaxBtnWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 10));
        syntaxBtnWrap.add(syntaxBtn);
        messageHeaderPanel.add(syntaxBtnWrap, BorderLayout.EAST);


        // Set up Analysis Area
        analysisArea = new JTextArea();
        analysisArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        analysisArea.setBorder(BorderFactory.createLineBorder(Color.BLACK));
        analysisArea.setEditable(false);

        analysisScroll = new JScrollPane(analysisArea);
        analysisScroll.getVerticalScrollBar().putClientProperty("JScrollBar.fastWheelScrolling", true);

        // Code Screen
        codeArea = new RSyntaxTextArea(20, 60);
        codeArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVA);
        codeArea.setCodeFoldingEnabled(true);
        codeArea.setAntiAliasingEnabled(true);
        codeArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        codeArea.setBracketMatchingEnabled(true);
        codeArea.setAutoIndentEnabled(true);

        codeArea.setHighlightCurrentLine(true);
        codeArea.setBackground(Color.WHITE);
        codeArea.setForeground(Color.BLACK);
        codeArea.setCaretColor(Color.BLACK);
        codeArea.setCurrentLineHighlightColor(Color.LIGHT_GRAY);

        codeScroll = new RTextScrollPane(codeArea);
        codeScroll.getGutter().setLineNumberColor(Color.BLACK);
        codeScroll.getGutter().setBackground(Color.WHITE);
        codeScroll.getVerticalScrollBar().putClientProperty("JScrollBar.fastWheelScrolling", true);

        // Create Error handler area for Message mode
        errorArea = new JTextArea();
        errorArea.setRows(5);
        errorArea.setFont(new Font("Consolas", Font.BOLD, 14));
        errorArea.setEditable(false);
        errorArea.setBackground(new Color(230, 230, 230));
        errorArea.setText("Error Handler");

        errorScroll = new JScrollPane(errorArea);
        errorScroll.getVerticalScrollBar().putClientProperty("JScrollBar.fastWheelScrolling", true);

        // Tab Switches
        messageBtn.addActionListener(e -> switchMode("message"));
        svgBtn.addActionListener(e -> switchMode("svg"));
        javaBtn.addActionListener(e -> switchMode("java"));
        analysisBtn.addActionListener(e -> switchMode("analysis"));
        
        syntaxBtn.addActionListener(e -> showSyntaxDialog());


        // ---------------- SAVE (cross-platform, default = Documents/DynamicDuoExports) ----------------
        saveBtn.addActionListener(e -> {

            String ext = switch (currentMode) {
                case "java" -> ".java";
                case "analysis" -> ".txt";
                case "svg" -> ".svg";
                default -> ".txt";
            };

            String defaultName = switch (currentMode) {
                case "java" -> "ProtocolDemo.java";
                case "message" -> "protocol.txt";
                case "analysis" -> "analysis.txt";
                case "svg" -> "CryptoDiagram.svg";
                default -> "output" + ext;
            };

            File exportDir = getExportDirectory(); // <-- ALWAYS DynamicDuoExports

            JFileChooser chooser = new JFileChooser(exportDir);
            chooser.setDialogTitle("Save " + currentMode);
            chooser.setSelectedFile(new File(exportDir, defaultName));

            int option = chooser.showSaveDialog(this);
            if (option != JFileChooser.APPROVE_OPTION) {
                refocus();
                return;
            }

            File file = chooser.getSelectedFile();

            // ensure extension
            if (!file.getName().toLowerCase().endsWith(ext)) {
                file = new File(file.getAbsolutePath() + ext);
            }

            try {
                if (currentMode.equals("svg")) {
                    if (svgStr == null) {
                        JOptionPane.showMessageDialog(this, "There is no SVG to save");
                        refocus();
                        return;
                    }
                    Files.writeString(file.toPath(), svgStr, StandardCharsets.UTF_8);

                } else if (currentMode.equals("java") || currentMode.equals("message")) {
                    Files.writeString(file.toPath(), codeArea.getText(), StandardCharsets.UTF_8);

                } else { // analysis
                    Files.writeString(file.toPath(), analysisArea.getText(), StandardCharsets.UTF_8);
                }

                JOptionPane.showMessageDialog(this, "File saved: " + file.getAbsolutePath());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Error saving file: " + ex.getMessage());
            }

            refocus();
        });


        // ---------------- UPLOAD (cross-platform, default = Documents/DynamicDuoExports) ----------------
        uploadBtn.addActionListener(e -> {
            File exportDir = getExportDirectory();

            JFileChooser chooser = new JFileChooser(exportDir);
            chooser.setDialogTitle("Upload Protocol (.txt or .pdf)");

            chooser.setAcceptAllFileFilterUsed(true);
            chooser.addChoosableFileFilter(new FileNameExtensionFilter("Text files (*.txt)", "txt"));
            chooser.addChoosableFileFilter(new FileNameExtensionFilter("PDF files (*.pdf)", "pdf"));

            int option = chooser.showOpenDialog(this);
            if (option != JFileChooser.APPROVE_OPTION) {
                refocus();
                return;
            }

            File file = chooser.getSelectedFile();

            String lower = file.getName().toLowerCase();
            try {
                if (lower.endsWith(".pdf")) {
                    try (PDDocument document = PDDocument.load(file)) {
                        PDFTextStripper stripper = new PDFTextStripper();
                        String text = stripper.getText(document);
                        codeArea.setText(text);
                    }
                } else {
                    String text = Files.readString(file.toPath(), StandardCharsets.UTF_8);
                    codeArea.setText(text);
                }

                modeBuffers.put(currentMode, codeArea.getText());
                JOptionPane.showMessageDialog(this, "File loaded: " + file.getAbsolutePath());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "Error loading file: " + ex.getMessage());
            }

            refocus();
        });


        // Dark mode toggle
        displayBtn.addActionListener(e -> {
            if (dark) {
                codeScroll.getGutter().setLineNumberColor(Color.BLACK);
                codeScroll.getGutter().setBackground(Color.WHITE);
                navPanel.setBackground(Color.WHITE);
                buttonPanel.setBackground(Color.WHITE);
                codeArea.setBackground(Color.WHITE);
                codeArea.setForeground(Color.BLACK);
                codeArea.setCaretColor(Color.BLACK);
                codeArea.setCurrentLineHighlightColor(Color.LIGHT_GRAY);
                headingArea.setBackground(new Color(230, 230, 230));
                headingArea.setForeground(Color.BLACK);
                analysisArea.setBackground(Color.WHITE);
                analysisArea.setForeground(Color.BLACK);
                errorArea.setBackground(new Color(230, 230, 230));
                errorArea.setForeground(Color.BLACK);
                displayBtn.setText("Dark Mode");
                dark = false;
                labelDark();
            } else {
                codeScroll.getGutter().setLineNumberColor(Color.WHITE);
                codeScroll.getGutter().setBackground(new Color(40, 44, 52));
                navPanel.setBackground(Color.DARK_GRAY);
                buttonPanel.setBackground(Color.DARK_GRAY);
                codeArea.setBackground(new Color(40, 44, 52));
                codeArea.setForeground(Color.WHITE);
                codeArea.setCaretColor(Color.WHITE);
                codeArea.setCurrentLineHighlightColor(new Color(50, 56, 66));
                headingArea.setBackground(Color.DARK_GRAY);
                headingArea.setForeground(Color.WHITE);
                analysisArea.setBackground(new Color(40, 44, 52));
                analysisArea.setForeground(Color.WHITE);
                errorArea.setBackground(Color.DARK_GRAY);
                errorArea.setForeground(Color.WHITE);
                displayBtn.setText("Light Mode");
                dark = true;
                labelDark();
            }
            refocus();
        });

        runBtn.addActionListener(e -> {

            String input = codeArea.getText();
            Lexer lexer = new Lexer(input);
            ProtocolParser parser = new ProtocolParser(lexer);

            try {
                ProtocolNode tree = parser.parse();

                System.out.println("=== AST ===");
                System.out.println(tree.pretty());

                lastProtocol = tree;

                svgStr = SequenceDiagramFromAst.renderTwoParty(tree);
                analysisStr = KnowledgeAnalyzer.analyzeToString(tree);

                executed = true;
                errorArea.setText("No errors detected.");

            } catch (ParseException pe) {
                System.err.println("Parse error: " + pe.getMessage());
                System.err.println("Line: " + pe.getLine());
                errorArea.setText("Parse error: " + pe.getMessage() + "\nLine: " + pe.getLine());
                executed = false;
            } catch (Exception re) {
                System.err.println("Render failed: " + re.getMessage());
                errorArea.setText("Render failed: " + re.getMessage());
                executed = false;
            }

            if (executed) {
                svgStr = svgStr.replace("stroke=\"transparent\"", "stroke=\"none\"");
                switchMode("svg");
            }

        });

        switchMode("message");
    }

    // Highlight the active mode button
    private void highlightActiveMode(JButton active) {
        JButton[] allButtons = { messageBtn, svgBtn, javaBtn, analysisBtn };
        for (JButton b : allButtons) {
            if (b == active) {
                b.setBackground(Color.LIGHT_GRAY);
            } else {
                b.setBackground(new Color(238, 238, 238));
            }
        }
    }

    // Switch editor between modes and remember content
    private void switchMode(String newMode) {
        if (currentMode.equals("java") || currentMode.equals("message")) {
            modeBuffers.put(currentMode, codeArea.getText());
        } else if (newMode.equals("analysis")) {
            modeBuffers.put(currentMode, analysisArea.getText());
        }

        currentMode = newMode;

        String content = modeBuffers.getOrDefault(newMode, "");
        if (newMode.equals("java") || newMode.equals("message")) {
            codeArea.setText(content);
        } else if (newMode.equals("analysis")) {
            analysisArea.setText(content);
        }

        zoomFactor = 1.0;

        switch (newMode) {
            case "svg" -> {
                headingArea.setText("SVG Mode\n(This is the SVG for the Message Passing)");
                highlightActiveMode(svgBtn);


                uploadBtn.setEnabled(false);
                runBtn.setEnabled(false);
                syntaxBtn.setEnabled(false);


                if (executed && svgStr != null) {
                    SVGUniverse universe = new SVGUniverse();
                    URI svgUri = universe.loadSVG(new StringReader(svgStr), "graph");

                    SVGIcon icon = new SVGIcon();
                    icon.setSvgUniverse(universe);
                    icon.setSvgURI(svgUri);

                    icon.setAntiAlias(true);
                    icon.setAutosize(SVGIcon.AUTOSIZE_BESTFIT);

                    label = new JLabel(icon);
                    label.revalidate();
                    label.repaint();
                } else {
                    label.setIcon(null);
                    label.setText("No SVG generated yet. Please run the message first or check for errors.");
                }

                label.setHorizontalAlignment(JLabel.CENTER);

                svgScroll = new JScrollPane(label);
                svgScroll.getVerticalScrollBar().setUnitIncrement(15);
                svgScroll.revalidate();
                svgScroll.repaint();

                splitPane4 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, headingScroll, svgScroll);
                splitPane4.setResizeWeight(0.1);
                setCenterComponent(splitPane4);

                splitPane4.revalidate();
                splitPane4.repaint();

                zoom(splitPane4);
                splitPane4.addKeyListener(this);
                splitPane4.setFocusable(true);
                splitPane4.requestFocusInWindow();
                labelDark();
            }
            case "java" -> {
                headingArea.setText("Java Code \n(Generated starter code from protocol)");
                highlightActiveMode(javaBtn);

                if (executed && lastProtocol != null) {
                    try {
                        String javaCode = JavaCodeGenerator.fromProtocol(lastProtocol);
                        codeArea.setText(javaCode);
                    } catch (Exception ex) {
                        ex.printStackTrace();
                        codeArea.setText("""
                            Error generating starter Java code from protocol.

                            Details:
                            """ + ex.getMessage());
                    }
                } else {
                    codeArea.setText("No code available. Please run the message first or check for errors.");
                }

                codeArea.setEditable(false);
                uploadBtn.setEnabled(false);
                runBtn.setEnabled(false);
                syntaxBtn.setEnabled(false);


                setUpCodeScroll();
                setCenterComponent(splitPane);
                zoom(splitPane);
                splitPane.addKeyListener(this);
                splitPane.setFocusable(true);
                splitPane.requestFocusInWindow();
            }
            case "analysis" -> {
                headingArea.setText("Analysis Mode\n(This is what parts of the message have been leaked)");
                if (executed) {
                    analysisArea.setText("Analysis Results\n" + analysisStr);
                } else {
                    analysisArea.setText("No analysis available. Please run the message first or check for errors.");
                }

                highlightActiveMode(analysisBtn);
                uploadBtn.setEnabled(false);
                runBtn.setEnabled(false);
                syntaxBtn.setEnabled(false);


                splitPane2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, headingScroll, analysisScroll);
                splitPane2.setResizeWeight(0.10);
                setCenterComponent(splitPane2);

                zoom(splitPane2);
                splitPane2.addKeyListener(this);
                splitPane2.setFocusable(true);
                splitPane2.requestFocusInWindow();
            }
            case "message" -> {
                splitPane3 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, splitPane, errorScroll);

                headingArea.setText(" Welcome to the Protocol Editor. Please type your protocol description below, then click 'Run'. \n You may refer to the syntax guide for help -->");

                highlightActiveMode(messageBtn);
                

                syntaxBtn.setEnabled(true);
                codeArea.setEditable(true);
                uploadBtn.setEnabled(true);
                runBtn.setEnabled(true);

                setUpCodeScroll();

                // Header (with Syntax button on the right) + Editor
                JSplitPane top = new JSplitPane(JSplitPane.VERTICAL_SPLIT, messageHeaderPanel, codeScroll);
                top.setResizeWeight(0.20);     // header smaller, editor bigger
                top.setDividerSize(6);

                splitPane3 = new JSplitPane(JSplitPane.VERTICAL_SPLIT, top, errorScroll);
                splitPane3.setResizeWeight(0.80);
                setCenterComponent(splitPane3);


            }
        }
    }

    private void setCenterComponent(Component comp) {
        Container contentPane = getContentPane();
        BorderLayout layout = (BorderLayout) contentPane.getLayout();
        Component oldCenter = layout.getLayoutComponent(BorderLayout.CENTER);

        if (oldCenter != null) {
            contentPane.remove(oldCenter);
        }

        contentPane.add(comp, BorderLayout.CENTER);
        revalidate();
        repaint();
    }

    private void setUpCodeScroll() {
        Component header = currentMode.equals("message") ? messageHeaderPanel : headingScroll;
        splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, header, codeScroll);
        splitPane.setResizeWeight(0.25);
    }



    @Override
    public void keyPressed(KeyEvent e) {
        JSplitPane ext = switch (currentMode) {
            case "java" -> splitPane;
            case "svg" -> splitPane4;
            case "analysis" -> splitPane2;
            default -> splitPane3;
        };

        if (e.getKeyCode() == KeyEvent.VK_EQUALS && e.isControlDown()) {
            zoomFactor += .1;
            zoom(ext);
        } else if (e.getKeyCode() == KeyEvent.VK_MINUS && e.isControlDown()) {
            zoomFactor -= .1;
            zoom(ext);
        } else if (e.getKeyCode() == KeyEvent.VK_0 && e.isControlDown()) {
            zoomFactor = 1.0;
            zoom(ext);
        }
    }

    public void zoom(JSplitPane ext) {
        Component[] arr = new Component[3];
        arr[0] = ext.getTopComponent();
        arr[1] = ext.getBottomComponent();

        int num = 2;

        if (arr[0] instanceof JSplitPane inner) {
            arr[0] = inner.getTopComponent();
            arr[2] = inner.getBottomComponent();
            num = 3;
        }

        for (int i = 0; i < num; i++) {
            if (arr[i] instanceof JScrollPane) {
                JScrollPane scrollPane = (JScrollPane) arr[i];
                JViewport viewport = scrollPane.getViewport();
                Component view = viewport.getView();

                if (view instanceof JTextArea textArea) {
                    textArea.setFont(textArea.getFont().deriveFont((float) (16f * zoomFactor)));
                } else if (view instanceof JLabel label && currentMode.equals("svg") &&
                        executed && svgStr != null) {
                    SVGUniverse universe = new SVGUniverse();
                    URI svgUri = universe.loadSVG(new StringReader(svgStr), "graph");

                    SVGIcon icon = new SVGIcon();
                    icon.setSvgUniverse(universe);
                    icon.setSvgURI(svgUri);

                    icon.setAntiAlias(true);
                    icon.setAutosize(SVGIcon.AUTOSIZE_BESTFIT);

                    int originalWidth = icon.getIconWidth();
                    int originalHeight = icon.getIconHeight();

                    int newWidth = (int) (originalWidth * zoomFactor);
                    int newHeight = (int) (originalHeight * zoomFactor);

                    icon.setPreferredSize(new Dimension(newWidth, newHeight));
                    label.setIcon(icon);
                } else if (view instanceof RSyntaxTextArea rSyntaxTextArea) {
                    rSyntaxTextArea.setFont(rSyntaxTextArea.getFont().deriveFont((float) (14f * zoomFactor)));
                } else if (view instanceof JLabel label) {
                    label.setFont(label.getFont().deriveFont((float) (14f * zoomFactor)));
                }
            }
        }
    }

    @Override public void keyReleased(KeyEvent e) {}
    @Override public void keyTyped(KeyEvent e) {}

    public void labelDark() {
        if (dark) {
            label.setBackground(new Color(40, 44, 52));
            label.setForeground(Color.WHITE);
        } else {
            label.setBackground(Color.LIGHT_GRAY);
            label.setForeground(Color.BLACK);
        }
        label.setOpaque(true);
    }

    public void refocus() {
        JSplitPane ext = switch (currentMode) {
            case "java" -> splitPane;
            case "svg" -> splitPane4;
            case "analysis" -> splitPane2;
            default -> splitPane3;
        };
        ext.requestFocusInWindow();
    }

    // ---------------- Directory helpers ----------------

    private File getDocumentsDirectory() {
    File docs = FileSystemView.getFileSystemView().getDefaultDirectory(); // usually “Documents”
    if (docs != null && docs.exists()) return docs;
    return new File(System.getProperty("user.home")); // fallback
    }

    private File getExportDirectory() {
        File dir = new File(getDocumentsDirectory(), "DynamicDuoExports");
        if (!dir.exists()) dir.mkdirs();
        return dir;
    }

    /*
     * Show the syntax dialog
     */
    private void showSyntaxDialog() {
        String text = loadSyntaxText();

        JTextArea area = new JTextArea(text);
        area.setEditable(false);
        area.setLineWrap(false);
        area.setFont(new Font("Consolas", Font.PLAIN, 13));

        JScrollPane scroll = new JScrollPane(area);
        scroll.setPreferredSize(new Dimension(820, 520));

        // ---- Build a real modal dialog so we can control colors reliably ----
        final JDialog dialog = new JDialog(this, "Syntax Reference (SYNTAX.md)", true);
        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JButton okBtn = new JButton("OK");
        okBtn.addActionListener(e -> dialog.dispose());

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        bottom.add(okBtn);

        JPanel root = new JPanel(new BorderLayout());
        root.add(scroll, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);

        // ---- Apply light/dark theme ----
        applySyntaxDialogTheme(dialog, root, area, scroll, bottom);

        dialog.setContentPane(root);
        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);

        refocus();
    }


    private String loadSyntaxText() {
        try (InputStream in = GUI.class.getResourceAsStream("/SYNTAX.md")) {
            if (in == null) {
                return "SYNTAX.md not found inside the jar.\n\n" +
                    "Fix: put SYNTAX.md in src/main/resources/";
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error loading SYNTAX.md: " + e.getMessage();
        }
    }

    /*
     * Apply the theme to the syntax dialog components
     */
    private void applySyntaxDialogTheme(
            JDialog dialog,
            JPanel root,
            JTextArea area,
            JScrollPane scroll,
            JPanel bottom
    ) {
        if (dark) {
            Color bg = new Color(40, 44, 52);
            Color panelBg = new Color(30, 33, 39);
            Color fg = Color.WHITE;

            dialog.getContentPane().setBackground(bg);
            root.setBackground(bg);
            bottom.setBackground(panelBg);

            area.setBackground(bg);
            area.setForeground(fg);
            area.setCaretColor(fg);

            scroll.getViewport().setBackground(bg);
            scroll.setBackground(bg);
        } else {
            Color bg = Color.WHITE;
            Color panelBg = new Color(245, 245, 245);
            Color fg = Color.BLACK;

            dialog.getContentPane().setBackground(bg);
            root.setBackground(bg);
            bottom.setBackground(panelBg);

            area.setBackground(bg);
            area.setForeground(fg);
            area.setCaretColor(fg);

            scroll.getViewport().setBackground(bg);
            scroll.setBackground(bg);
        }
    }



}
