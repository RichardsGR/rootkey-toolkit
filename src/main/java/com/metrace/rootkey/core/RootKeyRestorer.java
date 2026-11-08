package com.metrace.rootkey.core;

import com.metrace.rootkey.RootKeyException;
import com.metrace.rootkey.internal.Codec;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 根密钥还原器：四个组件 XOR 合并，并做多重校验。
 *
 * <p>还原是纯函数：给定同一组组件，任意时间、任意次数还原结果完全一致（稳定性保障）。
 * 还原时依次校验：</p>
 * <ol>
 *   <li>组件文件自身 checksum（在 {@link ComponentFile#load} 中完成）</li>
 *   <li>四个标签恰好为 a/b/c/d（防止重复/缺失）</li>
 *   <li>keyId、KCV 四份一致（防止混入其他根密钥的组件）</li>
 *   <li>还原结果 KCV 与组件记录匹配（最终自证）</li>
 * </ol>
 */
public final class RootKeyRestorer {

    private RootKeyRestorer() {
    }

    /** 按配置位置加载四个组件并还原 */
    public static RootKeySecret restore(Path a, Path b, Path c, Path d) {
        List<ComponentFile> files = new ArrayList<ComponentFile>();
        for (Path p : Arrays.asList(a, b, c, d)) {
            files.add(ComponentFile.load(p));
        }
        return restoreFiles(files);
    }

    /** 对已加载的四个组件做还原（组件顺序无关） */
    public static RootKeySecret restoreFiles(List<ComponentFile> comps) {
        if (comps == null || comps.size() != 4) {
            throw new RootKeyException("还原需要恰好 4 个组件，实际 " + (comps == null ? 0 : comps.size()));
        }

        // 1) 标签集合必须是 {a,b,c,d}
        Set<Character> labels = new HashSet<Character>();
        Set<Character> duplicated = new HashSet<Character>();
        for (ComponentFile cf : comps) {
            if (!labels.add(cf.label())) {
                duplicated.add(cf.label());
            }
        }
        Set<Character> missing = new HashSet<Character>(
                Arrays.asList(Character.valueOf('a'), Character.valueOf('b'),
                        Character.valueOf('c'), Character.valueOf('d')));
        missing.removeAll(labels);
        if (!duplicated.isEmpty() || !missing.isEmpty()) {
            throw new RootKeyException("组件标签校验失败: 重复=" + duplicated + " 缺失=" + missing
                    + "（请确认传入的是 a/b/c/d 四个不同组件）");
        }

        // 2) keyId / KCV 四份一致
        String keyId = comps.get(0).keyId();
        String kcv = comps.get(0).kcvHex();
        for (ComponentFile cf : comps) {
            if (!keyId.equals(cf.keyId())) {
                throw new RootKeyException("组件 keyId 不一致: '" + keyId + "' vs '" + cf.keyId()
                        + "'（组件可能来自不同的生成批次）");
            }
            if (!kcv.equalsIgnoreCase(cf.kcvHex())) {
                throw new RootKeyException("组件 KCV 不一致（可能混入了其他根密钥的组件）");
            }
        }

        // 3) XOR 合并（顺序无关）+ KCV 自证
        byte[] key = Codec.xorAll(comps.get(0).material(), comps.get(1).material(),
                comps.get(2).material(), comps.get(3).material());
        String actualKcv = RootKeySecret.computeKcv(key);
        if (!actualKcv.equalsIgnoreCase(kcv)) {
            throw new RootKeyException("KCV 校验失败: 还原结果 " + actualKcv + " 与组件记录 " + kcv.toLowerCase()
                    + " 不一致，请确认四个组件来自同一根密钥且未被篡改");
        }
        return new RootKeySecret(keyId, kcv.toLowerCase(), key);
    }
}
