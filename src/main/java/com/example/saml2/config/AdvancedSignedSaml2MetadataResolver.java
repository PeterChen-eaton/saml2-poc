package com.example.saml2.config;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;

/**
 * 生产级SAML2 Metadata签名解析器
 * 使用OpenSAML进行符合标准的XML数字签名
 * 确保签名的完整性和不可否认性
 */
@Component
public class AdvancedSignedSaml2MetadataResolver {

    private static final Logger logger = LoggerFactory.getLogger(AdvancedSignedSaml2MetadataResolver.class);

    @Autowired
    private Saml2MetadataResolver defaultMetadataResolver;

    public AdvancedSignedSaml2MetadataResolver() {
        try {
            OpenSamlInitializationService.initialize();
            logger.info("OpenSAML initialized for production metadata signing");
        } catch (Exception e) {
            logger.error("Failed to initialize OpenSAML for production signing", e);
            throw new RuntimeException("OpenSAML initialization failed", e);
        }
    }

    /**
     * 解析并生成生产级签名的SAML metadata
     * 使用OpenSAML进行符合XML-DSIG标准的数字签名
     */
    public String resolveWithAdvancedSignature(RelyingPartyRegistration relyingPartyRegistration) {
        try {
            // 获取默认metadata
            String defaultMetadata = defaultMetadataResolver.resolve(relyingPartyRegistration);
            
            // 获取签名凭据
            Saml2X509Credential signingCredential = getSigningCredential(relyingPartyRegistration);
            if (signingCredential == null) {
                throw new IllegalStateException("No signing credential found for metadata signing");
            }

            // 使用OpenSAML进行真正的签名
            return signWithOpenSAML(defaultMetadata, signingCredential);
            
        } catch (Exception e) {
            logger.error("Failed to resolve signed metadata", e);
            throw new RuntimeException("Metadata signing failed", e);
        }
    }

    /**
     * 使用OpenSAML进行符合标准的XML数字签名
     * 生成可验证的生产级metadata签名
     */
    private String signWithOpenSAML(String metadataXml, Saml2X509Credential signingCredential) {
        try {
            // 解析XML为DOM
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            Document document = db.parse(new ByteArrayInputStream(metadataXml.getBytes("UTF-8")));

            // 解析为OpenSAML对象
            Element element = document.getDocumentElement();
            Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                .getUnmarshaller(element);
            
            if (unmarshaller == null) {
                throw new IllegalStateException("No unmarshaller found for metadata element");
            }

            XMLObject xmlObject = unmarshaller.unmarshall(element);
            
            if (!(xmlObject instanceof EntityDescriptor)) {
                throw new IllegalStateException("Metadata is not an EntityDescriptor");
            }

            EntityDescriptor entityDescriptor = (EntityDescriptor) xmlObject;

            // 创建OpenSAML凭据
            BasicCredential credential = new BasicCredential(
                signingCredential.getCertificate().getPublicKey(),
                signingCredential.getPrivateKey()
            );

            // 配置签名参数
            SignatureSigningParameters signingParameters = new SignatureSigningParameters();
            signingParameters.setSigningCredential(credential);
            signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            signingParameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);

            // 对EntityDescriptor进行签名
            SignatureSupport.signObject(entityDescriptor, signingParameters);

            // 转换回XML字符串
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory()
                .getMarshaller(entityDescriptor);
            Element signedElement = marshaller.marshall(entityDescriptor);

            // 转换为字符串
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(signedElement), new StreamResult(writer));

            logger.info("Metadata signed successfully with OpenSAML");
            return writer.toString();

        } catch (Exception e) {
            logger.error("Failed to sign metadata with OpenSAML: " + e.getMessage(), e);
            throw new RuntimeException("OpenSAML metadata signing failed", e);
        }
    }

    /**
     * 获取签名凭据
     */
    private Saml2X509Credential getSigningCredential(RelyingPartyRegistration relyingPartyRegistration) {
        return relyingPartyRegistration.getSigningX509Credentials().stream()
            .findFirst()
            .orElse(null);
    }
}
