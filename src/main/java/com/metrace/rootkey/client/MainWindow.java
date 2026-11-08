package com.metrace.rootkey.client;

import com.metrace.rootkey.RootKeyConstants;
import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.RootKeyManager;
import com.metrace.rootkey.config.RootKeyConfig;
import com.metrace.rootkey.core.ComponentFile;
import com.metrace.rootkey.core.RootKeyGenerator;
import com.metrace.rootkey.core.RootKeyRestorer;
import com.metrace.rootkey.core.RootKeySecret;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * 客户端主窗口：四个页签（生成 / 校验还原 / 加密 / 解密），
 * 每个操作都在 SwingWorker 后台线程调用 SDK，完成后回到事件线程渲染结果。
 */
final class MainWindow extends JFrame {

    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final Color OK_GREEN = new Color(0x15803D);
    private static final Color ERR_RED = new Color(0xB91C1C);
    private static final Color KCV_BLUE = new Color(0x1D4ED8);

    private final JLabel statusBar = new JLabel("就绪 · 根密钥永不显示，只显示 KCV 指纹");

    MainWindow() {
        super("RootKey 管理台 v" + RootKeyConstants.TOOL_VERSION);
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("① 生成组件", buildGenerateTab());
        tabs.addTab("② 校验与还原", buildVerifyTab());
        tabs.addTab("③ 加密", buildEncryptTab());
        tabs.addTab("④ 解密", buildDecryptTab());

        JPanel root = new JPanel(new BorderLayout());
        root.add(tabs, BorderLayout.CENTER);
        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        statusBar.setFont(statusBar.getFont().deriveFont(12f));
        statusBar.setForeground(new Color(0x64748B));
        bottom.add(statusBar, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);

        setContentPane(root);
        pack();
        setSize(Math.max(640, getWidth()), Math.max(560, getHeight()));
        setLocationRelativeTo(null);
    }

    // ================================================================== ① 生成

    private JPanel buildGenerateTab() {
        final JTextField keyId = new JTextField();
        final JTextField outDir = new JTextField();
        final JCheckBox force = new JCheckBox("目标目录已有文件时覆盖（--force）");
        final JButton browse = browseButton(outDir);
        final JButton go = new JButton("生 成");
        final JTextArea result = monoArea(10);

        go.addActionListener(e -> {
            String dirText = outDir.getText().trim();
            if (dirText.isEmpty()) {
                warn("请先选择组件输出目录");
                return;
            }
            go.setEnabled(false);
            status("生成中…");
            final String kid = keyId.getText().trim();
            final Path dir = Paths.get(dirText).toAbsolutePath().normalize();
            final boolean f = force.isSelected();
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    try (RootKeyGenerator.GenerateResult r =
                                 RootKeyManager.generate(dir, kid.isEmpty() ? null : kid, f)) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("keyId : ").append(r.keyId()).append('\n');
                        sb.append("KCV   : ").append(r.kcvHex())
                                .append("   （请记录，用于与服务器核对）\n");
                        List<Path> ps = r.componentPaths();
                        String[] labels = {"a", "b", "c", "d"};
                        for (int i = 0; i < ps.size(); i++) {
                            sb.append("组件 ").append(labels[i]).append("  →  ").append(ps.get(i))
                                    .append("  (").append(Files.size(ps.get(i))).append(" 字节)\n");
                        }
                        sb.append("manifest  →  ").append(r.manifestPath()).append('\n');
                        sb.append("\n请将四个组件分别存放于不同安全位置；四者同时泄露即等于根密钥泄露。");
                        return sb.toString();
                    }
                }

                @Override
                protected void done() {
                    go.setEnabled(true);
                    try {
                        String s = get();
                        result.setForeground(OK_GREEN);
                        result.setText(s);
                        status("生成成功（密钥本体未落盘）");
                    } catch (Exception ex) {
                        showError(ex);
                        result.setForeground(ERR_RED);
                        result.setText("生成失败：" + rootMessage(ex));
                    }
                }
            }.execute();
        });

        JPanel p = formPanel(
                rowWithBrowse("keyId（留空自动生成 rk-时间戳）", keyId, null),
                rowWithBrowse("输出目录", outDir, browse),
                force,
                go,
                sectionTitle("生成结果"),
                new JScrollPane(result)
        );
        return p;
    }

    // ================================================================== ② 校验

    private JPanel buildVerifyTab() {
        final JTextField dir = new JTextField();
        final JButton browse = browseButton(dir);
        final JButton go = new JButton("校 验");
        final JTextArea result = monoArea(12);

        go.addActionListener(e -> {
            Path d = requireDir(dir.getText(), "组件目录");
            if (d == null) {
                return;
            }
            go.setEnabled(false);
            status("校验中…");
            final Path compDir = d;
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    StringBuilder sb = new StringBuilder();
                    List<ComponentFile> comps = new java.util.ArrayList<ComponentFile>();
                    String[] labels = {"a", "b", "c", "d"};
                    boolean allOk = true;
                    for (int i = 0; i < 4; i++) {
                        Path p = compDir.resolve(labels[i] + RootKeyConstants.COMPONENT_FILE_SUFFIX);
                        try {
                            ComponentFile cf = ComponentFile.load(p);
                            comps.add(cf);
                            sb.append("[OK] 组件 ").append(labels[i]).append("  ").append(p)
                                    .append("  keyId=").append(cf.keyId()).append('\n');
                        } catch (RuntimeException ex) {
                            allOk = false;
                            sb.append("[失败] 组件 ").append(labels[i]).append("  ").append(p)
                                    .append("\n       ").append(ex.getMessage()).append('\n');
                        }
                    }
                    if (!allOk) {
                        sb.append('\n').append("组件文件存在损坏或缺失，未执行还原。");
                        throw new RootKeyException(sb.toString());
                    }
                    try (RootKeySecret secret = RootKeyRestorer.restoreFiles(comps)) {
                        sb.append("[OK] 标签 / keyId 一致性 / KCV 全部通过\n");
                        sb.append("[OK] 还原成功: keyId=").append(secret.keyId())
                                .append(", KCV=").append(secret.kcvHex());
                        return sb.toString();
                    }
                }

                @Override
                protected void done() {
                    go.setEnabled(true);
                    try {
                        String s = get();
                        result.setForeground(OK_GREEN);
                        result.setText(s);
                        status("校验完成");
                    } catch (Exception ex) {
                        result.setForeground(ERR_RED);
                        result.setText(rootMessage(ex));
                        status("校验未通过");
                    }
                }
            }.execute();
        });

        return formPanel(
                rowWithBrowse("组件目录（内含 a.comp ~ d.comp）", dir, browse),
                go,
                sectionTitle("校验结果"),
                new JScrollPane(result)
        );
    }

    // ================================================================== ③ 加密 / ④ 解密

    private JPanel buildEncryptTab() {
        final JTextField dir = new JTextField();
        final JButton browse = browseButton(dir);
        final JTextArea plain = new JTextArea(5, 40);
        plain.setLineWrap(true);
        plain.setWrapStyleWord(true);
        final JButton go = new JButton("加 密");
        final JTextArea result = monoArea(7);
        final JButton copy = copyButton(result);

        go.addActionListener(e -> {
            Path d = requireDir(dir.getText(), "组件目录");
            if (d == null || requireNonEmpty(plain.getText(), "明文") == null) {
                return;
            }
            runCryptoWorker(go, d, true, plain.getText(), result, copy);
        });

        JPanel p = formPanel(
                rowWithBrowse("组件目录", dir, browse),
                labeledArea("明文", plain),
                go,
                sectionTitle("密文（Base64）"),
                new JScrollPane(result),
                copy
        );
        return p;
    }

    private JPanel buildDecryptTab() {
        final JTextField dir = new JTextField();
        final JButton browse = browseButton(dir);
        final JTextArea cipher = monoArea(5);
        cipher.setLineWrap(true);
        final JButton go = new JButton("解 密");
        final JTextArea result = new JTextArea(6, 40);
        result.setEditable(false);
        result.setLineWrap(true);
        result.setWrapStyleWord(true);
        final JButton copy = copyButton(result);

        go.addActionListener(e -> {
            Path d = requireDir(dir.getText(), "组件目录");
            if (d == null || requireNonEmpty(cipher.getText(), "密文") == null) {
                return;
            }
            runCryptoWorker(go, d, false, cipher.getText(), result, copy);
        });

        return formPanel(
                rowWithBrowse("组件目录", dir, browse),
                labeledArea("密文（Base64）", cipher),
                go,
                sectionTitle("明文"),
                new JScrollPane(result),
                copy
        );
    }

    /** 加解密共用的后台任务：还原密钥 → SDK 加密/解密 → 回渲染 */
    private void runCryptoWorker(final JButton go, final Path dir, final boolean encrypt,
                                 final String input, final JTextArea result, final JButton copy) {
        go.setEnabled(false);
        copy.setVisible(false);
        status(encrypt ? "加密中…" : "解密中…");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                RootKeyConfig cfg = RootKeyConfig.builder()
                        .a(dir.resolve("a.comp")).b(dir.resolve("b.comp"))
                        .c(dir.resolve("c.comp")).d(dir.resolve("d.comp")).build();
                try (RootKeyManager km = new RootKeyManager(cfg)) {
                    return encrypt ? km.encryptToBase64(input) : km.decryptFromBase64(input);
                }
            }

            @Override
            protected void done() {
                go.setEnabled(true);
                try {
                    String s = get();
                    result.setForeground(encrypt ? new Color(0x0F172A) : OK_GREEN);
                    result.setText(s);
                    copy.setVisible(true);
                    status(encrypt ? "加密完成" : "解密完成");
                } catch (Exception ex) {
                    result.setForeground(ERR_RED);
                    result.setText("失败：" + rootMessage(ex));
                    status(encrypt ? "加密失败" : "解密失败");
                }
            }
        }.execute();
    }

    // ================================================================== UI 构件

    private JPanel formPanel(javax.swing.JComponent... items) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = 0;
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.insets = new Insets(6, 0, 6, 0);
        for (javax.swing.JComponent item : items) {
            p.add(item, c);
            c.gridy++;
        }
        return p;
    }

    private javax.swing.JComponent labeledArea(String label, JTextArea area) {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        JLabel l = new JLabel(label);
        l.setFont(l.getFont().deriveFont(12f));
        p.add(l, BorderLayout.NORTH);
        p.add(new JScrollPane(area), BorderLayout.CENTER);
        return p;
    }

    private javax.swing.JComponent rowWithBrowse(String label, JTextField field, JButton browse) {
        JPanel p = new JPanel(new BorderLayout(0, 4));
        JLabel l = new JLabel(label);
        l.setFont(l.getFont().deriveFont(12f));
        p.add(l, BorderLayout.NORTH);
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.add(field, BorderLayout.CENTER);
        if (browse != null) {
            row.add(browse, BorderLayout.EAST);
        }
        p.add(row, BorderLayout.CENTER);
        return p;
    }

    private javax.swing.JComponent sectionTitle(String title) {
        JLabel l = new JLabel(title);
        l.setFont(l.getFont().deriveFont(12f));
        l.setForeground(new Color(0x64748B));
        return l;
    }

    private JButton browseButton(final JTextField target) {
        JButton b = new JButton("浏览…");
        b.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                target.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        return b;
    }

    private JButton copyButton(final JTextArea source) {
        final JButton b = new JButton("复制到剪贴板");
        b.setVisible(false);
        b.addActionListener(e -> {
            Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new StringSelection(source.getText()), null);
            b.setText("已复制 ✓");
            javax.swing.Timer t = new javax.swing.Timer(1200, e2 -> b.setText("复制到剪贴板"));
            t.setRepeats(false);
            t.start();
        });
        return b;
    }

    private JTextArea monoArea(int rows) {
        JTextArea a = new JTextArea(rows, 40);
        a.setEditable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setFont(MONO);
        return a;
    }

    // ================================================================== 小工具

    /** 校验目录输入；不通过弹窗提示并返回 null */
    private Path requireDir(String text, String what) {
        if (text == null || text.trim().isEmpty()) {
            warn("请先选择" + what);
            return null;
        }
        Path d = Paths.get(text.trim());
        for (char label : RootKeyConstants.COMPONENT_LABELS) {
            if (!Files.isReadable(d.resolve(label + RootKeyConstants.COMPONENT_FILE_SUFFIX))) {
                warn(what + "缺少 " + d.resolve(label + RootKeyConstants.COMPONENT_FILE_SUFFIX));
                return null;
            }
        }
        return d;
    }

    private String requireNonEmpty(String s, String what) {
        if (s == null || s.trim().isEmpty()) {
            warn("请输入" + what);
            return null;
        }
        return s;
    }

    private void status(String s) {
        statusBar.setText(s);
    }

    private void warn(String msg) {
        JOptionPane.showMessageDialog(this, msg, "提示", JOptionPane.WARNING_MESSAGE);
    }

    private void showError(Exception ex) {
        Throwable cause = ex instanceof ExecutionException && ex.getCause() != null ? ex.getCause() : ex;
        JOptionPane.showMessageDialog(this, rootMessage(ex), "操作失败", JOptionPane.ERROR_MESSAGE);
        getRootPane().putClientProperty("last.error", cause);
    }

    private static String rootMessage(Throwable t) {
        Throwable cur = t;
        while (cur != null) {
            if (cur.getMessage() != null && !cur.getMessage().isEmpty()) {
                return cur.getMessage();
            }
            cur = cur.getCause();
        }
        return String.valueOf(t);
    }
}
