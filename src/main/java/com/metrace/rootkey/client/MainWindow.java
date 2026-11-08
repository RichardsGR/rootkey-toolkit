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
        tabs.addTab("⑤ 生成工作密钥", buildWorkKeyGenTab());
        tabs.addTab("⑥ 工作密钥·加解密", buildWorkKeyCryptTab());

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
                rowWithBrowse("组件目录（内含 a.txt ~ d.txt）", dir, browse),
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
                        .a(dir.resolve("a.txt")).b(dir.resolve("b.txt"))
                        .c(dir.resolve("c.txt")).d(dir.resolve("d.txt")).build();
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

    // ================================================================== ⑤ 生成工作密钥

    private JPanel buildWorkKeyGenTab() {
        final JTextField rootDir = new JTextField();
        final JTextField name = new JTextField();
        final JTextField outFile = new JTextField();
        final JCheckBox force = new JCheckBox("文件内已存在同名密钥时覆盖");
        final JButton go = new JButton("生 成");
        final JTextArea result = monoArea(10);

        go.addActionListener(e -> {
            Path root = requireDir(rootDir.getText(), "根密钥组件目录");
            if (root == null || requireNonEmpty(name.getText(), "工作密钥名称") == null) {
                return;
            }
            go.setEnabled(false);
            status("生成工作密钥中…");
            final Path rootPath = root;
            final String keyName = name.getText().trim();
            final Path out = outFile.getText().trim().isEmpty()
                    ? rootPath.getParent() == null
                      ? Paths.get(keyName + RootKeyConstants.WORKKEY_FILE_SUFFIX)
                      : rootPath.resolveSibling(keyName + RootKeyConstants.WORKKEY_FILE_SUFFIX)
                    : Paths.get(outFile.getText().trim());
            final boolean f = force.isSelected();
            new SwingWorker<String, Void>() {
                @Override
                protected String doInBackground() throws Exception {
                    try (RootKeyManager rootMgr = new RootKeyManager(rootConfigFor(rootPath));
                         com.metrace.rootkey.workkey.WorkKeyManager.Generated g =
                                 com.metrace.rootkey.workkey.WorkKeyManager.generate(out, keyName, rootMgr, f)) {
                        StringBuilder sb = new StringBuilder();
                        sb.append("名称    : ").append(g.name()).append('\n');
                        sb.append("KCV     : ").append(g.kcvHex()).append('\n');
                        sb.append("文件    : ").append(g.file()).append('\n');
                        sb.append("根密钥  : keyId=").append(rootMgr.keyId())
                                .append(", KCV=").append(rootMgr.kcv()).append('\n');
                        sb.append("文件内现有密钥: ").append(g.namesInFile()).append('\n');
                        sb.append("\n.json 文件可分发业务侧（可存多个工作密钥）；没有根密钥四组件无法还原。");
                        return sb.toString();
                    }
                }

                @Override
                protected void done() {
                    go.setEnabled(true);
                    try {
                        result.setForeground(OK_GREEN);
                        result.setText(get());
                        status("工作密钥已生成（文件只含密文材料）");
                    } catch (Exception ex) {
                        result.setForeground(ERR_RED);
                        result.setText("生成失败：" + rootMessage(ex));
                        status("生成失败");
                    }
                }
            }.execute();
        });

        return formPanel(
                rowWithBrowse("根密钥组件目录（内含 a.txt ~ d.txt）", rootDir, browseButton(rootDir)),
                rowWithBrowse("工作密钥名称", name, null),
                rowWithBrowse("输出文件（留空默认 <名称>.json）", outFile, null),
                force,
                go,
                sectionTitle("生成结果"),
                new JScrollPane(result)
        );
    }

    // ================================================================== ⑥ 工作密钥·加解密

    private JPanel buildWorkKeyCryptTab() {
        final JTextField rootDir = new JTextField();
        final JTextField wkFile = new JTextField();
        final JTextField wkName = new JTextField();
        final JTextArea plain = new JTextArea(3, 40);
        plain.setLineWrap(true);
        final JTextArea cipherIn = monoArea(3);
        final JTextArea cipherOut = monoArea(4);
        final JTextArea plainOut = new JTextArea(3, 40);
        plainOut.setEditable(false);
        plainOut.setLineWrap(true);
        final JButton verifyBtn = new JButton("还 原 校 验");
        final JButton encBtn = new JButton("加 密");
        final JButton decBtn = new JButton("解 密");

        verifyBtn.addActionListener(e -> {
            Path root = requireDir(rootDir.getText(), "根密钥组件目录");
            Path wk = requireWkFile(wkFile.getText());
            if (root == null || wk == null) {
                return;
            }
            runWkVerify(verifyBtn, root, wk, nameOrNull(wkName), cipherOut);
        });
        encBtn.addActionListener(e -> {
            Path root = requireDir(rootDir.getText(), "根密钥组件目录");
            Path wk = requireWkFile(wkFile.getText());
            if (root == null || wk == null || requireNonEmpty(plain.getText(), "明文") == null) {
                return;
            }
            runWkCrypto(encBtn, root, wk, nameOrNull(wkName), false, plain.getText(), cipherOut);
        });
        decBtn.addActionListener(e -> {
            Path root = requireDir(rootDir.getText(), "根密钥组件目录");
            Path wk = requireWkFile(wkFile.getText());
            if (root == null || wk == null || requireNonEmpty(cipherIn.getText(), "密文") == null) {
                return;
            }
            runWkCrypto(decBtn, root, wk, nameOrNull(wkName), true, cipherIn.getText(), plainOut);
        });

        return formPanel(
                rowWithBrowse("根密钥组件目录", rootDir, browseButton(rootDir)),
                rowWithBrowse("工作密钥文件（.json，可存多个密钥）", wkFile, browseFileButton(wkFile)),
                rowWithBrowse("密钥名称（文件内仅一个密钥时可留空）", wkName, null),
                verifyBtn,
                labeledArea("明文（加密）", plain),
                encBtn,
                sectionTitle("密文输出（Base64）"),
                new JScrollPane(cipherOut),
                labeledArea("密文输入（解密，Base64）", cipherIn),
                decBtn,
                sectionTitle("明文输出"),
                new JScrollPane(plainOut)
        );
    }

    /** 名称输入转 SDK 参数（空白视为 null） */
    private static String nameOrNull(JTextField field) {
        String s = field.getText();
        return s == null || s.trim().isEmpty() ? null : s.trim();
    }

    /** 校验工作密钥文件输入 */
    private Path requireWkFile(String text) {
        if (text == null || text.trim().isEmpty()) {
            warn("请先选择工作密钥文件");
            return null;
        }
        Path p = Paths.get(text.trim());
        if (!Files.isReadable(p)) {
            warn("工作密钥文件不存在或不可读: " + p);
            return null;
        }
        return p;
    }

    /** 后台还原校验：显示工作密钥名称与 KCV */
    private void runWkVerify(final JButton go, final Path rootPath, final Path wkPath,
                             final String keyName, final JTextArea result) {
        go.setEnabled(false);
        status("还原校验中…");
        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                try (RootKeyManager rootMgr = new RootKeyManager(rootConfigFor(rootPath));
                     com.metrace.rootkey.workkey.WorkKeySecret s =
                             com.metrace.rootkey.workkey.WorkKeyManager.restore(wkPath, keyName, rootMgr)) {
                    return "还原成功: 名称=" + s.name() + ", KCV=" + s.kcvHex();
                }
            }

            @Override
            protected void done() {
                go.setEnabled(true);
                try {
                    String s = get();
                    result.setForeground(OK_GREEN);
                    result.setText(s);
                    status("工作密钥还原校验通过");
                } catch (Exception ex) {
                    result.setForeground(ERR_RED);
                    result.setText(rootMessage(ex));
                    status("还原校验失败");
                }
            }
        }.execute();
    }

    /** 后台工作密钥加解密：decrypt=true 时 input 为 Base64 密文，否则为明文 */
    private void runWkCrypto(final JButton go, final Path rootPath, final Path wkPath, final String keyName,
                             final boolean decrypt, final String input, final JTextArea result) {
        go.setEnabled(false);
        status(decrypt ? "解密中…" : "加密中…");
        new SwingWorker<String[], Void>() {
            @Override
            protected String[] doInBackground() throws Exception {
                try (RootKeyManager rootMgr = new RootKeyManager(rootConfigFor(rootPath));
                     com.metrace.rootkey.workkey.WorkKeyManager wkm =
                             new com.metrace.rootkey.workkey.WorkKeyManager(rootMgr, wkPath, keyName)) {
                    String out = decrypt ? wkm.decryptFromBase64(input) : wkm.encryptToBase64(input);
                    return new String[]{out, wkm.name(), wkm.kcv()};
                }
            }

            @Override
            protected void done() {
                go.setEnabled(true);
                try {
                    String[] r = get();
                    result.setForeground(decrypt ? OK_GREEN : new Color(0x0F172A));
                    result.setText(r[0]);
                    status("完成（名称=" + r[1] + ", KCV=" + r[2] + "）");
                } catch (Exception ex) {
                    result.setForeground(ERR_RED);
                    result.setText("失败：" + rootMessage(ex));
                    status("操作失败");
                }
            }
        }.execute();
    }

    // ================================================================== UI 构件

    /** 由组件目录构建根密钥配置（a.txt ~ d.txt） */
    private static RootKeyConfig rootConfigFor(Path rootDir) {
        return RootKeyConfig.builder()
                .a(rootDir.resolve("a.txt")).b(rootDir.resolve("b.txt"))
                .c(rootDir.resolve("c.txt")).d(rootDir.resolve("d.txt")).build();
    }

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
        return chooserButton(target, JFileChooser.DIRECTORIES_ONLY);
    }

    private JButton browseFileButton(final JTextField target) {
        return chooserButton(target, JFileChooser.FILES_ONLY);
    }

    private JButton chooserButton(final JTextField target, final int mode) {
        JButton b = new JButton("浏览…");
        b.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setFileSelectionMode(mode);
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
