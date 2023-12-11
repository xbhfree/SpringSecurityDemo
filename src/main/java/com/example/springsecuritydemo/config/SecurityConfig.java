package com.example.springsecuritydemo.config;

import com.example.springsecuritydemo.service.MyUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class SecurityConfig{
    //设置用户名密码
    /*@Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("123")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }*/

/*

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
*/

 /*   @Bean
    public UserDetailsManager users(DataSource dataSource){
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("123"))
                .roles("USER")
                .build();
        JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
        users.createUser(user);
        return users;
    }
*/
    //注入数据源
    @Autowired
    private DataSource dataSource;
    @Bean
    public PersistentTokenRepository persistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //自动生成数据库表
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }
   @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private MyUserDetailService myUserDetailService;

    /*@Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception{
        AuthenticationManager manager = httpSecurity
                .getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(myUserDetailService)
                .and()
                .build();
        return manager;

    }*/
    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(myUserDetailService);
        ProviderManager providerManager = new ProviderManager(provider);
        return providerManager;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //对AuthenticationManager的第二种写法
        /*AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(myUserDetailService);
        AuthenticationManager build = authenticationManagerBuilder.build();*/
        return http
                //.authenticationManager(build) //对AuthenticationManager的第二种写法
                .authorizeHttpRequests(authorizeHttpRequests-> //在这个后面开始配置URL相关的【URL访问权限控制相关的】
                        authorizeHttpRequests.requestMatchers("/login","/test/hello").permitAll() //permitAll:授予所有权限【匿名可以访问的、不用登录就可以访问】
                                .anyRequest() //任何的请求
                                .authenticated() //需要认证【登录】后才能访问
                )

                .formLogin(formLogin->
                        formLogin.loginPage("/login") //登录页面
                                .loginProcessingUrl("/login").permitAll() //登录接口可以匿名访问
                                .defaultSuccessUrl("/index.html") //登录成功访问/index页面

                )
                .csrf(Customizer.withDefaults()) //关闭跨域漏洞攻击防护
                .exceptionHandling(new Customizer<ExceptionHandlingConfigurer<HttpSecurity>>() {
                    @Override
                    public void customize(ExceptionHandlingConfigurer<HttpSecurity> httpSecurityExceptionHandlingConfigurer) {
                        httpSecurityExceptionHandlingConfigurer.accessDeniedPage("/access-denied2.html");
                    }
                })
                //.logout(logout->logout.logoutUrl("/logout").logoutSuccessUrl("/login"))
                .logout(logout->logout.logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET")).logoutSuccessUrl("/login"))
                /*.logout(new Customizer<LogoutConfigurer<HttpSecurity>>() {
                    @Override
                    public void customize(LogoutConfigurer<HttpSecurity> httpSecurityLogoutConfigurer) {
                        httpSecurityLogoutConfigurer
                                .logoutUrl("/logout")
                                .logoutSuccessUrl("/login")
                                .deleteCookies("JSESSIONID")
                                .invalidateHttpSession(true)
                                .permitAll();
                    }
                })*/
                //设置记住我
                .rememberMe(t -> t.tokenRepository(persistentTokenRepository()).tokenValiditySeconds(60).userDetailsService(myUserDetailService))
                .build();

    }


}