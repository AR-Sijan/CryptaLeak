package com.cryptaleak.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * Project CryptaLeak - Modern Dark Theme System
 * 
 * Provides unified enterprise styling across all Swing frames, tables,
 * inputs, badges, and terminal logs.
 */
public final class DarkTheme {

    // Palette Colors
    public static final Color BG_DARKEST = new Color(0x0D, 0x11, 0x17); // #0D1117 (Deep Obsidian)
    public static final Color BG_CARD = new Color(0x16, 0x1B, 0x22);    // #161B22 (Card Slate)
    public static final Color BG_INPUT = new Color(0x21, 0x26, 0x2D);   // #21262D (Input Field)
    public static final Color BG_HOVER = new Color(0x30, 0x36, 0x3D);   // #30363D (Hover State)
    public static final Color BORDER_COLOR = new Color(0x30, 0x36, 0x3D);

    public static final Color FG_PRIMARY = new Color(0xF0, 0xF6, 0xFC); // Primary White
    public static final Color FG_MUTED = new Color(0x8B, 0x94, 0x9E);   // Secondary Muted
    public static final Color FG_SUBTLE = new Color(0x6E, 0x76, 0x81);

    // Threat & Telemetry Accents
    public static final Color ACCENT_CYAN = new Color(0x58, 0xA6, 0xFF);  // #58A6FF
    public static final Color ACCENT_BLUE = new Color(0x1F, 0x6F, 0xEB);  // Primary Buttons
    public static final Color ACCENT_RED = new Color(0xF8, 0x51, 0x49);   // Breach / Critical
    public static final Color ACCENT_GREEN = new Color(0x3F, 0xB9, 0x50); // Secure / Clean
    public static final Color ACCENT_AMBER = new Color(0xD2, 0x99, 0x22); // Warning / Medium
    public static final Color ACCENT_PURPLE = new Color(0xBC, 0x8C, 0xFF);// Honeytokens

    // Fonts
    public static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 20);
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 15);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_MONO = new Font("Consolas", Font.PLAIN, 12);
    public static final Font FONT_MONO_BOLD = new Font("Consolas", Font.BOLD, 12);

    private DarkTheme() {}

    public static void applyThemeToFrame(JFrame frame) {
        frame.getContentPane().setBackground(BG_DARKEST);
        try {
            UIManager.put("Panel.background", BG_DARKEST);
            UIManager.put("OptionPane.background", BG_CARD);
            UIManager.put("OptionPane.messageForeground", FG_PRIMARY);
        } catch (Exception ignored) {}
    }

    public static JButton createButton(String text, Color bg, Color fg) {
        JButton button = new JButton(text);
        button.setBackground(bg);
        button.setForeground(fg);
        button.setFont(FONT_BODY_BOLD);
        button.setFocusPainted(false);
        button.setBorder(new CompoundBorder(
                new LineBorder(bg.darker(), 1, true),
                new EmptyBorder(7, 14, 7, 14)
        ));
        button.setCursor(new Cursor(Cursor.HAND_CURSOR));

        button.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent e) {
                button.setBackground(bg.brighter());
            }
            @Override
            public void mouseExited(java.awt.event.MouseEvent e) {
                button.setBackground(bg);
            }
        });

        return button;
    }

    public static JTextField createTextField(int columns) {
        JTextField tf = new JTextField(columns);
        styleInputComponent(tf);
        return tf;
    }

    public static JPasswordField createPasswordField(int columns) {
        JPasswordField pf = new JPasswordField(columns);
        styleInputComponent(pf);
        return pf;
    }

    private static void styleInputComponent(JTextField field) {
        field.setBackground(BG_INPUT);
        field.setForeground(FG_PRIMARY);
        field.setCaretColor(ACCENT_CYAN);
        field.setFont(FONT_BODY);
        field.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(6, 10, 6, 10)
        ));
    }

    public static JPanel createCardPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(BG_CARD);
        panel.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(12, 14, 12, 14)
        ));
        return panel;
    }

    public static JPanel createMetricBadge(String label, String value, Color valueColor) {
        JPanel badge = new JPanel(new BorderLayout(4, 4));
        badge.setBackground(BG_CARD);
        badge.setBorder(new CompoundBorder(
                new LineBorder(BORDER_COLOR, 1, true),
                new EmptyBorder(10, 16, 10, 16)
        ));

        JLabel lblTitle = new JLabel(label.toUpperCase());
        lblTitle.setFont(FONT_SMALL);
        lblTitle.setForeground(FG_MUTED);

        JLabel lblValue = new JLabel(value);
        lblValue.setFont(new Font("Segoe UI", Font.BOLD, 22));
        lblValue.setForeground(valueColor);

        badge.add(lblTitle, BorderLayout.NORTH);
        badge.add(lblValue, BorderLayout.CENTER);
        return badge;
    }

    public static void styleTable(JTable table) {
        table.setBackground(BG_CARD);
        table.setForeground(FG_PRIMARY);
        table.setGridColor(BORDER_COLOR);
        table.setFont(FONT_BODY);
        table.setRowHeight(28);
        table.setSelectionBackground(new Color(0x23, 0x36, 0x4D));
        table.setSelectionForeground(FG_PRIMARY);
        table.setShowGrid(true);

        JTableHeader header = table.getTableHeader();
        header.setBackground(BG_INPUT);
        header.setForeground(FG_MUTED);
        header.setFont(FONT_BODY_BOLD);
        header.setBorder(new LineBorder(BORDER_COLOR));

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
        centerRenderer.setBackground(BG_CARD);
        centerRenderer.setForeground(FG_PRIMARY);

        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
    }

    public static JTextArea createConsoleArea() {
        JTextArea area = new JTextArea();
        area.setBackground(new Color(0x08, 0x0A, 0x0D));
        area.setForeground(new Color(0x5A, 0xF7, 0x8E)); // Phosphor terminal green
        area.setCaretColor(FG_PRIMARY);
        area.setFont(FONT_MONO);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setMargin(new Insets(8, 8, 8, 8));
        return area;
    }
}