# 当前秘密封装

`secret_envelope` 提供当前 SGEV 封装的成熟 HKDF-SHA256 和 AES-256-GCM 运算。
产品拥有 domain、当前 revision 和对象 binding；公共库不按产品名或历史版本选择算法。

已知编译期定义使用 `seal::<D>` / `open::<D>`。
从已验证签名材料取得定义的独立工具使用 `seal_with_domain` / `open_with_domain`：

```rust
open_with_domain(&master, domain, revision, binding, envelope)?;
```

动态与泛型接口调用同一实现。预期 revision 来自调用方的当前权威定义，不能从不可信封装头取值后自行信任。
不符的 magic 或 revision、错误 domain/binding、修改过的密文和超过预算的输入均拒绝；没有另一格式解析或历史回退。
domain 最多为 u16 可表达的字节长度，binding 最多 4096 字节，明文最多 1 MiB。
随机 nonce 使用操作系统随机源；主密钥和解密明文继续由公共秘密类型保护。

`src/secret_envelope/fixtures/current-envelope-v1.json` 是独立生成的公开校验样例。
测试实际核对密钥派生、AAD 字节、封装长度与解密结果，并验证静态/动态接口交互。
其中主密钥及 nonce 是公开的测试值，不能用来创建生产凭据。

本轮 Linux 行为验证与原生平台验证分别记录；没有新增平台支持声明，也不把 Linux 验证作为移动设备实测。
