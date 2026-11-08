package com.metrace.rootkey.client;

import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.GraphicsEnvironment;
import java.awt.image.BufferedImage;
import java.io.File;
import javax.imageio.ImageIO;

/**
 * 根密钥管理客户端（桌面图形界面）。
 *
 * <p>纯 Swing 实现（JDK 内置，零新增依赖），内部直接调用 SDK 门面
 * {@code RootKeyManager / RootKeyGenerator / ComponentFile}，
 * 不经过任何网络层。安全约定与 SDK 一致：任何界面只显示 KCV 指纹，
 * 根密钥本体与组件材料永不输出。</p>
 *
 * <p>启动方式：</p>
 * <pre>
 *   rootkey client                       # CLI 子命令
 *   java -cp rootkey-toolkit.jar com.metrace.rootkey.client.RootKeyClient
 *   双击 RootKeyToolkit.app（jpackage 打包产物）
 * </pre>
 */
public final class RootKeyClient {

    private RootKeyClient() {
    }

    public static void main(String[] args) {
        // 隐藏参数：--screenshot-test <png>，渲染一帧后退出（用于无人工的 UI 自检）
        String screenshotPath = null;
        for (int i = 0; i < args.length - 1; i++) {
            if ("--screenshot-test".equals(args[i])) {
                screenshotPath = args[i + 1];
            }
        }
        final String shot = screenshotPath;
        launch(shot);
    }

    /** 打开客户端窗口。AWT 事件线程是非守护线程，调用方 main 返回后 JVM 继续存活。 */
    public static void launch() {
        launch(null);
    }

    private static void launch(final String screenshotPath) {
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("[错误] 当前环境无图形界面（headless），请在本机桌面运行客户端；"
                    + "服务器场景请使用 CLI 或 SDK。");
            System.exit(1);
        }
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                try {
                    UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
                } catch (Exception ignore) {
                    // 系统外观不可用时使用默认外观，不影响功能
                }
                final MainWindow window = new MainWindow();
                window.setVisible(true);
                if (screenshotPath != null) {
                    scheduleSelfScreenshot(window, screenshotPath);
                }
            }
        });
    }

    /** 渲染当前窗口到 PNG 后退出进程（仅用于构建自检） */
    private static void scheduleSelfScreenshot(final MainWindow window, final String path) {
        Timer t = new Timer(700, null);
        t.setRepeats(false);
        t.addActionListener(e -> {
            try {
                int w = window.getWidth(), h = window.getHeight();
                BufferedImage img = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
                window.paint(img.createGraphics());
                ImageIO.write(img, "png", new File(path));
                System.out.println("[自检] 窗口已渲染到 " + path);
            } catch (Exception ex) {
                System.err.println("[自检失败] " + ex);
            } finally {
                System.exit(0);
            }
        });
        t.start();
    }
}
