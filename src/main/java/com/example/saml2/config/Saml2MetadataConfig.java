package com.example.saml2.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Configuration
public class Saml2MetadataConfig {

    private static final Logger logger = LoggerFactory.getLogger(Saml2MetadataConfig.class);

    // SP配置 - 可通过外部配置文件或环境变量覆盖
    @Value("${saml2.sp.entity-id:http://localhost:8080/saml2/service-provider-metadata/default}")
    private String spEntityId;
    
    @Value("${saml2.sp.acs-url:http://localhost:8080/login/saml2/sso/default}")
    private String acsUrl;
    
    @Value("${saml2.sp.slo-url:http://localhost:8080/logout/saml2/slo}")
    private String sloUrl;
    
    @Value("${saml2.idp.metadata-location:saml2/idp-metadata.xml}")
    private String metadataLocation;

    // SP证书配置（可选）
    @Value("${saml2.sp.keystore.location:classpath:certificates/sp-keystore.p12}")
    private String keystoreLocation;
    
    @Value("${saml2.sp.keystore.password:changeit}")
    private String keystorePassword;
    
    @Value("${saml2.sp.keystore.alias:sp-cert}")
    private String keystoreAlias;
    
    // Registration ID配置 - 用于标识这个SAML2配置
    @Value("${saml2.sp.registration-id:default}")
    private String registrationId;

    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws IOException {
        logger.info("Initializing SAML2 RelyingPartyRegistrationRepository...");
        
        // 检查metadata文件是否存在
        ClassPathResource metadataResource = new ClassPathResource(metadataLocation);
        
        // 从metadata文件加载IdP配置
        logger.info("Loading IdP metadata from: " + metadataLocation);
        RelyingPartyRegistration.Builder builder = RelyingPartyRegistrations
            .fromMetadataLocation(metadataResource.getURL().toString())
            .registrationId(registrationId);
        
        // 配置SP证书（用于metadata显示）
        Saml2X509Credential signingCredential = loadSpCertificate();
        if (signingCredential != null) {
            // 添加证书到metadata中，Spring Security会自动使用它们
            builder.signingX509Credentials(credentials -> credentials.add(signingCredential));
            // 为解密创建单独的凭据
            Saml2X509Credential decryptionCredential = loadSpDecryptionCertificate();
            if (decryptionCredential != null) {
                builder.decryptionX509Credentials(credentials -> credentials.add(decryptionCredential));
            }
            logger.info("SP signing certificate loaded successfully");
            logger.info("SP decryption certificate loaded successfully");
        } else {
            logger.info("SP certificate not found - metadata will be generated without certificate information");
        }
        
        // 配置SP信息
        RelyingPartyRegistration registration = builder
            .entityId(spEntityId)
            .assertionConsumerServiceLocation(acsUrl)
            .singleLogoutServiceLocation(sloUrl)
            .build();
        
        logger.info("SAML2 registration created successfully with ID: " + registrationId);
        return new InMemoryRelyingPartyRegistrationRepository(registration);        
    }

    /**
     * 加载SP的P12证书
     */
    private Saml2X509Credential loadSpCertificate() {
        try {
            // 加载keystore
            KeyStore keystore = loadKeystore();
            if (keystore == null) {
                return null;
            }
            
            // 获取私钥和证书
            PrivateKey privateKey = (PrivateKey) keystore.getKey(keystoreAlias, keystorePassword.toCharArray());
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keystoreAlias);
            
            if (privateKey == null || certificate == null) {
                logger.warn("SP certificate or private key not found with alias: {}", keystoreAlias);
                return null;
            }
            
            logger.info("SP certificate loaded successfully for alias: {}", keystoreAlias);
            return Saml2X509Credential.signing(privateKey, certificate);
        } catch (Exception e) {
            logger.error("Failed to load SP certificate from: " + keystoreLocation, e);
            return null;
        }
    }

    /**
     * 加载SP的P12证书用于解密
     */
    private Saml2X509Credential loadSpDecryptionCertificate() {
        try {
            // 加载keystore
            KeyStore keystore = loadKeystore();
            if (keystore == null) {
                return null;
            }
            
            // 获取私钥和证书
            PrivateKey privateKey = (PrivateKey) keystore.getKey(keystoreAlias, keystorePassword.toCharArray());
            X509Certificate certificate = (X509Certificate) keystore.getCertificate(keystoreAlias);
            
            if (privateKey == null || certificate == null) {
                logger.warn("SP decryption certificate or private key not found with alias: {}", keystoreAlias);
                return null;
            }
            
            logger.info("SP decryption certificate loaded successfully for alias: {}", keystoreAlias);
            return Saml2X509Credential.decryption(privateKey, certificate);
        } catch (Exception e) {
            logger.error("Failed to load SP decryption certificate from: " + keystoreLocation, e);
            return null;
        }
    }

    /**
     * 加载keystore文件
     */
    private KeyStore loadKeystore() {
        try {
            // 检查keystore文件是否存在
            Resource keystoreResource;
            if (keystoreLocation.startsWith("classpath:")) {
                keystoreResource = new ClassPathResource(keystoreLocation.substring("classpath:".length()));
            } else if (keystoreLocation.startsWith("file:")) {
                keystoreResource = new org.springframework.core.io.FileSystemResource(keystoreLocation.substring("file:".length()));
            } else {
                keystoreResource = new ClassPathResource(keystoreLocation);
            }
            
            if (!keystoreResource.exists()) {
                logger.debug("SP keystore not found: {}", keystoreLocation);
                return null;
            }
            
            // 加载P12证书
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(keystoreResource.getInputStream(), keystorePassword.toCharArray());
            return keystore;
        } catch (Exception e) {
            logger.error("Failed to load keystore from: " + keystoreLocation, e);
            return null;
        }
    }
}
