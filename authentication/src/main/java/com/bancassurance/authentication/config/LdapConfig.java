package com.bancassurance.authentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

import java.util.HashMap;
import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "ldap")
public class LdapConfig {
    
    private String url;
    private String base;
    private String username;
    private String password;
    private String userSearchBase;
    private String userSearchFilter;
    private String groupSearchBase;
    private String groupRoleAttribute;

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(url);
        contextSource.setBase(base);
        contextSource.setUserDn(username);
        contextSource.setPassword(password);
        
        // Handle AD referrals
        Map<String, Object> baseEnvironmentProperties = new HashMap<>();
        baseEnvironmentProperties.put("java.naming.referral", "follow");
        baseEnvironmentProperties.put("com.sun.jndi.ldap.connect.timeout", "5000");
        baseEnvironmentProperties.put("com.sun.jndi.ldap.read.timeout", "5000");
        contextSource.setBaseEnvironmentProperties(baseEnvironmentProperties);
        
        contextSource.afterPropertiesSet();
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        return new LdapTemplate(contextSource());
    }

    // Getters and Setters
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    
    public String getBase() { return base; }
    public void setBase(String base) { this.base = base; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public String getUserSearchBase() { return userSearchBase; }
    public void setUserSearchBase(String userSearchBase) { this.userSearchBase = userSearchBase; }
    
    public String getUserSearchFilter() { return userSearchFilter; }
    public void setUserSearchFilter(String userSearchFilter) { this.userSearchFilter = userSearchFilter; }
    
    public String getGroupSearchBase() { return groupSearchBase; }
    public void setGroupSearchBase(String groupSearchBase) { this.groupSearchBase = groupSearchBase; }
    
    public String getGroupRoleAttribute() { return groupRoleAttribute; }
    public void setGroupRoleAttribute(String groupRoleAttribute) { this.groupRoleAttribute = groupRoleAttribute; }
}