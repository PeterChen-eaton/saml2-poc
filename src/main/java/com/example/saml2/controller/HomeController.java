package com.example.saml2.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

    @GetMapping("/")
    public String home() {
        logger.info("Accessing home page");
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        logger.info("Accessing login page");
        return "login";
    }

    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication, Model model) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            
            if (principal instanceof Saml2AuthenticatedPrincipal) {
                Saml2AuthenticatedPrincipal saml2Principal = (Saml2AuthenticatedPrincipal) principal;
                logger.info("User authenticated via SAML2: {}", saml2Principal.getName());
                model.addAttribute("username", saml2Principal.getName());
                model.addAttribute("attributes", saml2Principal.getAttributes());
                model.addAttribute("authMethod", "SAML2");
                
                // 记录所有属性用于调试
                saml2Principal.getAttributes().forEach((key, value) -> 
                    logger.debug("SAML2 Attribute - {}: {}", key, value)
                );
            } else {
                logger.info("User authenticated via other method: {}", principal.getClass().getSimpleName());
                model.addAttribute("username", authentication.getName());
                model.addAttribute("authMethod", "Other");
            }
        } else {
            logger.warn("No authentication found or user not authenticated");
            model.addAttribute("error", "Not authenticated");
        }
        return "dashboard";
    }

    @GetMapping("/error")
    public String error() {
        return "error";
    }
}
