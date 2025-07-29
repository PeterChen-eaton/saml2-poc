package com.example.saml2.controller;

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
 * 提供 SP metadata 给 IdP 使用
 */
@Controller
public class Saml2MetadataController {

    @Autowired
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    @Autowired
    private Saml2MetadataResolver saml2MetadataResolver;

    /**
     * 获取 SP metadata
     * 
     * @param registrationId SAML2 registration ID
     * @return SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata/{registrationId}", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getMetadata(@PathVariable("registrationId") String registrationId) {
        RelyingPartyRegistration relyingPartyRegistration = 
            this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
        
        if (relyingPartyRegistration == null) {
            throw new IllegalArgumentException("Unknown registrationId: " + registrationId);
        }

        return this.saml2MetadataResolver.resolve(relyingPartyRegistration);
    }

    /**
     * 获取默认 SP metadata
     * 
     * @return 默认的 SP metadata XML
     */
    @GetMapping(value = "/saml2/metadata", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getDefaultMetadata() {
        return getMetadata("default");
    }

    /**
     * 获取 SP metadata (兼容旧路径)
     * 
     * @param registrationId SAML2 registration ID
     * @return SP metadata XML
     */
    @GetMapping(value = "/saml2/service-provider-metadata/{registrationId}", produces = MediaType.APPLICATION_XML_VALUE)
    @ResponseBody
    public String getServiceProviderMetadata(@PathVariable("registrationId") String registrationId) {
        return getMetadata(registrationId);
    }
}
