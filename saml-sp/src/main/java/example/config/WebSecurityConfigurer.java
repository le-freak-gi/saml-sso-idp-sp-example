package example.config;

import java.util.ArrayList;
import java.util.List;

import javax.servlet.SessionCookieConfig;

import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import example.saml.sp.SamlContextProvider;
import example.saml.sp.SamlSsoEntryPoint;
import example.saml.sp.Assertion.SamlAssertionConsumeFilter;
import example.saml.sp.Assertion.SamlAssertionConsumerImpl;
import example.saml.sp.Authentication.SamlAuthenticationProvider;

@Configuration
@EnableWebSecurity
public class WebSecurityConfigurer extends WebSecurityConfigurerAdapter {

    @Value("${sp.acs}")
    private String acs;
    
    @Value("${sp.dest}")
    private String dest;

    @Bean(initMethod = "initialize")
    public ParserPool parserPool() {
        return new StaticBasicParserPool();
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/error", acs + "/**", dest + "/**").permitAll()
                .anyRequest().authenticated()
                .and()
            .httpBasic()
                .authenticationEntryPoint(samlSsoEntryPoint())
                .and()
            .addFilterAfter(samlFilterChain(), BasicAuthenticationFilter.class)
            .csrf().disable();
    }

    @Bean
    public SamlSsoEntryPoint samlSsoEntryPoint() {
        return new SamlSsoEntryPoint();
    }
    
    @Bean
    public FilterChainProxy samlFilterChain() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<>();
        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(acs + "/**"), samlFilter()));
        return new FilterChainProxy(chains);
    }
    
    @Override
    public void configure(AuthenticationManagerBuilder authBuilder) {
        authBuilder.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new SamlAuthenticationProvider().assertionConsumer(assertionConsumer());
    }

    @Bean
    public SamlAssertionConsumerImpl assertionConsumer() {
        return new SamlAssertionConsumerImpl();
    }
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            SessionCookieConfig sessionCookieConfig = servletContext.getSessionCookieConfig();
            sessionCookieConfig.setName("sp.session");
            sessionCookieConfig.setHttpOnly(true);
        };
    }

    @Bean
    public SamlAssertionConsumeFilter samlFilter() throws Exception {
        SamlAssertionConsumeFilter samlFilter = new SamlAssertionConsumeFilter(acs);
        samlFilter.samlContextProvider(samlContextProvider());
        samlFilter.setAuthenticationManager(authenticationManagerBean());
        samlFilter.setAuthenticationSuccessHandler(successRedirectHandler());
        return samlFilter;
    }

    @Bean
    public SamlContextProvider samlContextProvider() {
        return new SamlContextProvider();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }    

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/user");
        return successRedirectHandler;
    }
    
}