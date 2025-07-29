# SP证书文件信息

## P12证书文件
- **文件名**: sp-keystore.p12
- **密码**: changeit
- **别名**: sp-cert
- **算法**: RSA 2048位
- **有效期**: 10年 (2025-07-28 至 2035-07-26)

## 文件说明
- **sp-keystore.p12**: P12格式的密钥库，包含私钥和证书，用于SAML2 metadata显示
- **sp-certificate.crt**: 导出的公钥证书，可提供给IdP进行验证

## 使用方法
证书已在 `application.properties` 中配置，会自动在SP metadata中显示证书信息。

⚠️ **注意**: 这是测试证书，仅用于开发环境，生产环境请使用CA签发的证书。
