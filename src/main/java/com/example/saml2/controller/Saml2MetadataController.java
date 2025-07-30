package com.example.saml2.controller;

import com.example.saml2.config.AdvancedSignedSaml2MetadataResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * SAML2 Metadata Controller
 * 提供SP metadata给IdP使用
 * - 默认提供生产级签名的metadata
 * - 提供无签名版本用于开发测试
 */
@Controller
public class Saml2MetadataController {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    private Saml2MetadataResolver saml2MetadataResolver;
    
    @Autowired
    private AdvancedSignedSaml2MetadataResolver advancedSignedSaml2MetadataResolver;

    /**
     * 获取无签名的SP metadata（仅用于开发测试）
     * 
     * @param registrationId SAML2 registration ID
     * @return SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata/{registrationId}/unsigned", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getUnsignedMetadata(@PathVariable("registrationId") String registrationId) {
        RelyingPartyRegistration relyingPartyRegistration = 
            this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        
        if (relyingPartyRegistration == null) {
            throw new IllegalArgumentException("Unknown registrationId: " + registrationId);
        }

        return this.saml2MetadataResolver.resolve(relyingPartyRegistration);
    }

    /**
     * 获取生产级签名的SP metadata（推荐使用）
     * 
     * @param registrationId SAML2 registration ID
     * @return 使用OpenSAML签名的生产级SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata/{registrationId}", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getMetadata(@PathVariable("registrationId") String registrationId) {
        RelyingPartyRegistration relyingPartyRegistration = 
            this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        
        if (relyingPartyRegistration == null) {
            throw new IllegalArgumentException("Unknown registrationId: " + registrationId);
        }

        return this.advancedSignedSaml2MetadataResolver.resolveWithAdvancedSignature(relyingPartyRegistration);
    }

    /**
     * 获取默认SP metadata（生产级签名）
     * 
     * @return 默认的使用OpenSAML签名的SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getDefaultMetadata() {
        return getMetadata("default");
    }

    /**
     * 获取默认无签名SP metadata（仅用于开发测试）
     * 
     * @return 默认的无签名SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata/unsigned", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getDefaultUnsignedMetadata() {
        return getUnsignedMetadata("default");
    }

}
