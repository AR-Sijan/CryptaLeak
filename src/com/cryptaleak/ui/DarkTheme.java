package com.cryptaleak.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.geom.RoundRectangle2D;

public final class DarkTheme {

    // Palette Colors
    public static final Color BG_DARKEST = new Color(0x0B, 0x0F, 0x19); // #0B0F19 (Primary)
    public static final Color BG_CARD = new Color(0x16, 0x1F, 0x30);    // #161F30 (Card)
    public static final Color BG_INPUT = new Color(0x0B, 0x0F, 0x19);   // Inside input fields
    public static final Color BG_HOVER = new Color(0x1F, 0x2E, 0x47);   // Hover
    public static final Color BORDER_COLOR = new Color(0x1F, 0x2E, 0x47); // #1F2E47

    public static final Color FG_PRIMARY = new Color(0xF0, 0xF6, 0xFC); // Primary White
    public static final Color FG_MUTED = new Color(0x8B, 0x94, 0x9E);   // Secondary Muted
    public static final Color FG_SUBTLE = new Color(0x6E, 0x76, 0x81);

    // Threat & Telemetry Accents
    public static final Color ACCENT_CYAN = new Color(0x00, 0xD2, 0xFF);  // #00D2FF
    public static final Color ACCENT_BLUE = new Color(0x00, 0x88, 0xFF);  // Primary Buttons
    public static final Color ACCENT_RED = new Color(0xFF, 0x33, 0x66);   // #FF3366 Danger
    public static final Color ACCENT_GREEN = new Color(0x00, 0xE6, 0x76); // #00E676 Success
    public static final Color ACCENT_AMBER = new Color(0xFF, 0xAA, 0x00); // #FFAA00 Warning
    public static final Color ACCENT_PURPLE = new Color(0xBC, 0x8C, 0xFF);// Honeytokens

    // Fonts
    public static final Font FONT_HEADER = new Font("Segoe UI", Font.BOLD, 22);
    public static final Font FONT_TITLE = new Font("Segoe UI", Font.BOLD, 15);
    public static final Font FONT_BODY = new Font("Segoe UI", Font.PLAIN, 14);
    public static final Font FONT_BODY_BOLD = new Font("Segoe UI", Font.BOLD, 14);
    public static final Font FONT_SMALL = new Font("Segoe UI", Font.PLAIN, 12);
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
        return new RoundedButton(text, bg, fg);
    }

    public static JTextField createTextField(int columns) {
        return new RoundedTextField(columns);
    }

    public static JPasswordField createPasswordField(int columns) {
        return new RoundedPasswordField(columns);
    }

    public static JPanel createCardPanel() {
        return new RoundedPanel(BG_CARD, BORDER_COLOR, 12);
    }

    public static JPanel createMetricBadge(String label, String value, Color valueColor) {
        JPanel badge = new RoundedPanel(BG_CARD, BORDER_COLOR, 8);
        badge.setLayout(new BorderLayout(4, 4));
        badge.setBorder(new EmptyBorder(12, 16, 12, 16));

        JLabel lblTitle = new JLabel(label.toUpperCase());
        lblTitle.setFont(FONT_SMALL);
        lblTitle.setForeground(FG_MUTED);

        JLabel lblValue = new JLabel(value);
        lblValue.setFont(new Font("Segoe UI", Font.BOLD, 24));
        lblValue.setForeground(valueColor);

        badge.add(lblTitle, BorderLayout.NORTH);
        badge.add(lblValue, BorderLayout.CENTER);
        return badge;
    }

    // Modern toast notification implementation inside dashboard or frame
    public static void showToast(JFrame parent, String message, Color fgColor) {
        JDialog dialog = new JDialog(parent, false);
        dialog.setUndecorated(true);
        dialog.setBackground(new Color(0,0,0,0)); // Transparent bg
        
        RoundedPanel panel = new RoundedPanel(BG_CARD, fgColor, 15);
        panel.setLayout(new BorderLayout());
        panel.setBorder(new EmptyBorder(12, 24, 12, 24));
        
        JLabel msgLabel = new JLabel(message);
        msgLabel.setFont(FONT_BODY_BOLD);
        msgLabel.setForeground(fgColor);
        panel.add(msgLabel, BorderLayout.CENTER);
        
        dialog.add(panel);
        dialog.pack();
        
        int x, y;
        if (parent != null && parent.isVisible()) {
            x = parent.getX() + (parent.getWidth() - dialog.getWidth()) / 2;
            y = parent.getY() + 40; // Top toast
        } else {
            Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
            x = (screen.width - dialog.getWidth()) / 2;
            y = 40;
        }
        dialog.setLocation(x, y);
        dialog.setVisible(true);
        dialog.setAlwaysOnTop(true);
        
        new Thread(() -> {
            try {
                Thread.sleep(3500); // 3.5s auto-dismiss
                SwingUtilities.invokeLater(dialog::dispose);
            } catch (InterruptedException ignored) {}
        }).start();
    }

    // TABLE STYLING
    public static void styleTable(JTable table) {
        table.setBackground(BG_CARD);
        table.setForeground(FG_PRIMARY);
        table.setGridColor(BORDER_COLOR);
        table.setFont(FONT_BODY);
        table.setRowHeight(32); // Padded
        table.setSelectionBackground(BG_HOVER);
        table.setSelectionForeground(FG_PRIMARY);
        table.setShowGrid(true);
        table.setIntercellSpacing(new Dimension(0, 0));

        JTableHeader header = table.getTableHeader();
        header.setBackground(BG_DARKEST);
        header.setForeground(ACCENT_CYAN);
        header.setFont(FONT_BODY_BOLD);
        header.setBorder(BorderFactory.createMatteBorder(0,0,1,0, BORDER_COLOR));
        header.setPreferredSize(new Dimension(header.getWidth(), 36));

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
        area.setBackground(BG_DARKEST);
        area.setForeground(ACCENT_GREEN); // Phosphor terminal green
        area.setCaretColor(FG_PRIMARY);
        area.setFont(FONT_MONO);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setMargin(new Insets(12, 12, 12, 12));
        return area;
    }

    // --- CUSTOM ROUNDED COMPONENTS ---

    public static class RoundedPanel extends JPanel {
        private final Color bgColor;
        private final Color borderColor;
        private final int radius;

        public RoundedPanel(Color bgColor, Color borderColor, int radius) {
            super();
            this.bgColor = bgColor;
            this.borderColor = borderColor;
            this.radius = radius;
            setOpaque(false);
            setBorder(new EmptyBorder(radius/2, radius/2, radius/2, radius/2));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            // Draw background
            g2.setColor(bgColor);
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, radius, radius));
            
            // Draw border
            g2.setColor(borderColor);
            g2.draw(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, radius, radius));
            g2.dispose();
            super.paintComponent(g);
        }
    }

    public static class RoundedButton extends JButton {
        private final Color bgColor;
        private final Color fgColor;

        public RoundedButton(String text, Color bg, Color fg) {
            super(text);
            this.bgColor = bg;
            this.fgColor = fg;
            setForeground(fg);
            setFont(FONT_BODY_BOLD);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setCursor(new Cursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(10, 20, 10, 20));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            if (getModel().isPressed()) {
                g2.setColor(bgColor.darker());
            } else if (getModel().isRollover()) {
                g2.setColor(bgColor.brighter());
            } else {
                g2.setColor(bgColor);
            }
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 10, 10));

            // Optional subtle border
            g2.setColor(new Color(255, 255, 255, 30));
            g2.draw(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 10, 10));
            
            super.paintComponent(g2);
            g2.dispose();
        }
    }

    public static class RoundedTextField extends JTextField {
        public RoundedTextField(int columns) {
            super(columns);
            setOpaque(false);
            setForeground(FG_PRIMARY);
            setCaretColor(ACCENT_CYAN);
            setFont(FONT_BODY);
            setBorder(new EmptyBorder(8, 12, 8, 12));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            g2.setColor(BG_INPUT);
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));

            if (hasFocus()) {
                g2.setColor(ACCENT_CYAN);
            } else {
                g2.setColor(BORDER_COLOR);
            }
            g2.draw(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));

            super.paintComponent(g);
            g2.dispose();
        }
    }

    public static class RoundedPasswordField extends JPasswordField {
        public RoundedPasswordField(int columns) {
            super(columns);
            setOpaque(false);
            setForeground(FG_PRIMARY);
            setCaretColor(ACCENT_CYAN);
            setFont(FONT_BODY);
            setBorder(new EmptyBorder(8, 12, 8, 12));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            g2.setColor(BG_INPUT);
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));

            if (hasFocus()) {
                g2.setColor(ACCENT_CYAN);
            } else {
                g2.setColor(BORDER_COLOR);
            }
            g2.draw(new RoundRectangle2D.Float(0, 0, getWidth() - 1, getHeight() - 1, 8, 8));

            super.paintComponent(g);
            g2.dispose();
        }
    }
}