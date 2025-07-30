# SAML2 POC 项目

这是一个使用Spring Framework 6.2.3和Spring Security 6.2.3实现的SAML2登录示例项目，使用传统的XML配置方式，不使用Spring Boot。

## 🚀 技术栈

- **JDK**: 21
- **Spring Framework**: 6.2.3
- **Spring Security**: 6.2.3 
- **Thymeleaf**: 3.1.2 模板引擎
- **Maven**: 依赖管理
- **Jetty**: 11.0.19 内嵌服务器
- **XML配置**: 传统的Spring XML配置

## 📁 项目结构

```
saml2-poc/
├── src/main/
│   ├── java/com/example/saml2/
│   │   ├── config/Saml2MetadataConfig.java    # SAML2配置
│   │   └── controller/
│   │       ├── HomeController.java            # 主页控制器
│   │       └── Saml2MetadataController.java   # SP metadata端点
│   ├── resources/
│   │   ├── application.properties             # 应用配置
│   │   ├── saml2/idp-metadata.xml            # IdP元数据文件
│   │   ├── certificates/sp-keystore.p12      # SP证书(可选)
│   │   └── templates/                        # Thymeleaf模板
│   └── webapp/WEB-INF/
│       ├── web.xml                           # Web应用配置
│       ├── applicationContext.xml            # Spring根上下文
│       ├── dispatcher-servlet.xml            # Spring MVC配置
│       └── spring-security.xml               # Spring Security配置
```

## ⚡ 快速启动

### 1. 编译项目
```bash
mvn clean compile
```

### 2. 启动开发服务器
```bash
mvn jetty:run
```
应用将在 `http://localhost:8080` 启动

### 3. 打包部署
```bash
# 生成WAR文件
mvn clean package
# WAR文件: target/saml2-poc-1.0.0.war
# 可部署到Tomcat等服务器
```

## 🔧 SAML2 配置

### 两种IdP配置方式

#### 方式1: 直接配置（推荐，无需metadata文件）
如果您知道IdP的SSO URL，可以直接配置：

```properties
# 必需：IdP的SSO URL
saml2.idp.sso-url=https://your-idp.example.com/sso/saml

# 可选：IdP的Entity ID（如果不提供，将使用SSO URL）
saml2.idp.entity-id=https://your-idp.example.com

# 可选：单点登出URL
saml2.idp.slo-url=https://your-idp.example.com/slo/saml

# 注释掉metadata配置
# saml2.idp.metadata-location=
```

**常用IdP配置示例：**
```properties
# Keycloak
saml2.idp.sso-url=http://localhost:8090/auth/realms/demo/protocol/saml

# Azure AD
saml2.idp.sso-url=https://login.microsoftonline.com/{tenant-id}/saml2

# ADFS
saml2.idp.sso-url=https://your-adfs.company.com/adfs/ls/

# Okta
saml2.idp.sso-url=https://your-org.okta.com/app/your-app-id/sso/saml
```

#### IdP签名验证配置（推荐）
为了确保安全性，强烈建议配置IdP证书来验证SAML响应签名：

```properties
# IdP签名验证证书（从IdP获取）
saml2.idp.verification-cert=-----BEGIN CERTIFICATE-----
MIICmTCCAYECBgGDdOjmNTANBgkqhkiG9w0BAQsFADA...
-----END CERTIFICATE-----

# 或使用证书文件路径
# saml2.idp.verification-cert-location=classpath:certificates/idp-cert.pem
```

**获取IdP证书的方法：**
- **Okta**: 应用设置 → Sign On → View IdP metadata → 复制X509Certificate内容
- **Azure AD**: 单一登录 → SAML签名证书 → 下载证书(Base64)
- **ADFS**: 服务 → 证书 → 导出Token-signing证书
- **Keycloak**: Realm Settings → Keys → 复制RSA签名证书

> 📖 详细配置指南请参考：[docs/idp-signature-setup.md](docs/idp-signature-setup.md)

#### 方式2: 使用IdP Metadata文件（传统方式）
将IdP提供的metadata XML文件放置在：
```
src/main/resources/saml2/idp-metadata.xml
```

然后配置：
```properties
saml2.idp.metadata-location=saml2/idp-metadata.xml
```

**获取方式：**
- **Okta**: 管理控制台 > Applications > 您的SAML应用 > "View IdP metadata"
- **Azure AD**: Azure Portal > 企业应用程序 > 单一登录 > 下载"联合元数据XML"

### SP 配置
在 `application.properties` 中配置：
```properties
# Registration ID配置
saml2.sp.registration-id=default
saml2.sp.entity-id=http://localhost:8080/saml2/service-provider-metadata/default
saml2.sp.acs-url=http://localhost:8080/login/saml2/sso/default
saml2.sp.slo-url=http://localhost:8080/logout/saml2/slo

# 可选：SP证书配置（用于在metadata中显示证书信息）
saml2.sp.keystore.location=classpath:certificates/sp-keystore.p12
saml2.sp.keystore.password=changeit
saml2.sp.keystore.alias=sp-cert
```

### SP Metadata端点
启动应用后，可通过以下URL获取SP metadata：

- **主要端点**: `http://localhost:8080/saml2/metadata`
- **带registrationId**: `http://localhost:8080/saml2/metadata/default`
- **兼容端点**: `http://localhost:8080/saml2/service-provider-metadata/default`

使用curl命令导出：
```bash
curl -o sp-metadata.xml "http://localhost:8080/saml2/metadata"
```

## 🔐 P12证书配置 (可选)

用于在SP metadata中显示证书信息，增强安全性。项目已包含测试证书。

### 使用现有测试证书
项目已生成测试证书，密码：`changeit`

### 生成新证书
```bash
cd src/main/resources/certificates

# 使用keytool生成P12证书
keytool -genkeypair -alias sp-cert -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore sp-keystore.p12 \
  -validity 3650 -storepass changeit -keypass changeit \
  -dname "CN=SAML2 Test SP,OU=Development,O=Example Corp,C=US"
```

## 🌐 IdP配置示例

### Okta
- **Single sign on URL**: `http://localhost:8080/login/saml2/sso/default`
- **Audience URI**: `http://localhost:8080/saml2/service-provider-metadata/default`
- **Name ID format**: `EmailAddress`

### Azure AD
- **标识符(实体ID)**: `http://localhost:8080/saml2/service-provider-metadata/default`
- **回复URL**: `http://localhost:8080/login/saml2/sso/default`

## 📋 重要端点

- **主页**: `http://localhost:8080/`
- **仪表板**: `http://localhost:8080/dashboard` (需要认证)
- **SP Metadata**: `http://localhost:8080/saml2/metadata`
- **SAML SSO**: `http://localhost:8080/login/saml2/sso/default`
- **单点登出**: `http://localhost:8080/logout/saml2/slo`
- **登出**: `http://localhost:8080/logout`

## 🏗️ 架构说明

### 核心组件

1. **Saml2MetadataConfig.java** - SAML2配置类
   - 加载IdP metadata
   - 配置SP证书
   - 创建RelyingPartyRegistration

2. **Saml2MetadataController.java** - SP metadata端点
   - 提供多个metadata访问路径
   - 返回格式化的XML metadata

3. **spring-security.xml** - 安全配置
   - SAML2登录/登出配置
   - URL访问权限控制

### 特性

✅ **简化架构** - 使用Spring Security内置SAML2支持  
✅ **XML配置** - 传统Spring XML配置方式  
✅ **证书支持** - 可选的P12证书配置  
✅ **多端点** - 兼容多种metadata URL格式  
✅ **生产就绪** - 支持WAR部署  

## ⚠️ 注意事项

1. **测试证书**: 项目包含的P12证书仅用于测试，生产环境请使用CA签发的证书
2. **IdP Metadata**: 需要提供有效的IdP metadata文件
3. **网络配置**: 确保IdP能够访问SP的回调URL
4. **URL配置**: 根据实际部署环境调整配置中的URL

## 🔍 故障排除

### 查看日志
```bash
# 查看应用日志
tail -f logs/saml2-poc.log

# 或启动时查看控制台日志
mvn jetty:run
```

### 常见问题

1. **Metadata 404错误** - 确保应用完全启动后再访问metadata端点
2. **证书错误** - 检查P12证书路径和密码配置
3. **IdP连接失败** - 验证IdP metadata文件的有效性

### 调试模式
日志级别已配置为DEBUG，可以看到详细的SAML2交互信息。

## 📚 项目演进记录

本项目经历了以下主要演进：

1. **v1.0** - 复杂的自定义metadata签名实现
2. **v2.0** - 简化为Spring Security内置功能
3. **v3.0** - 移除不必要的签名功能，专注核心SAML2认证

当前版本专注于简洁性和可维护性，使用Spring Security 6.2.3的内置SAML2支持。

## 🤝 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 📄 许可证

本项目仅用于学习和测试目的。
