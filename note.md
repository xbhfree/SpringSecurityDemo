# 基础
## 基本原理
* spring security本质是过滤器链
  * FilterSecurityInterceptor  方法级过滤器，基本位于过滤链最底层
  * ExceptionTranslationFilter 异常过滤器，处理授权过程中抛出的异常
  * UsernamePasswordAuthenticationFilter 用户登录认证过滤器
* 过滤器加载过程
  * 使用SpringSecurity配置过滤器
    * DelegatingFilterProxy 中 doFilter --> initDelegate 获得固定名字FilterChainProxy
    * FilterChainProxy  doFilterInternal --> getFilters加载所有的过滤链
* 两个重要接口
  * UserDetailsService：实现该方法，查询数据库账号密码
    * 自定义验证账户密码步骤：
    * 创建类继承UsernamePasswordAuthenticationFilter，重写三个方法，查、成功、失败
    * 创建类实现UserDetailsService，编写查询过程，返回User对象，User对象由安全框架提供
  * PasswordEncoder：数据加密，用于返回User对象里密码的加密
    * 
    ``` java
    //创建  密码解析器
    BCryptPasswordEncoder encoder = new   BCryptPasswordEncoder();
    //加密
    String pwd = encoder.encode("password");
    //对比
    boolean result = encoder.matches("password",pwd);
    ```
    * BCryptPasswordEncoder是官方推荐密码解析器，对bcrtypt强散列方法的具体实现，是基于hash算法的单向加密，可以通过strength控制加密强度，默认为10
    
# web权限方案
## 认证
1. 设置登录的用户名和密码
   1. 第一种方案：配置application.properties文件
      ``` properties
      spring.security.user.name=xbh
      spring.security.user.password=123456
      ```
   2. 第二种方案：配置类
   该配置最新版已舍弃，需要用组件进行安全配置https://www.cnblogs.com/cnblog-user/p/16386942.html
   ```java
    import org.springframework.context.annotation.Bean;import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;import org.springframework.security.crypto.password.PasswordEncoder;@Configuration
      public class SecurityConfig extends WebSecurityConfigurerAdapter{
      @Override
      protected void configure(AuthenticationManagerBuilder auth)throws Exception{
      BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
      String password = encoder.encode("123");
      auth.inMemoryAuthentication().withUser("xbh").password(password).roles("admin");
      }
   
      @Bean
      PasswordEncoder password(){
        return new BCryptPasswordEncoder();
      }    
    }
   ```
   3.1.5版本的sb配置
    ``` java
    @Configuration
      public class SecurityConfiguration {
        @Bean
        public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
        .username("user")
        .password("123")
        .roles("USER")
        .build();
        return new InMemoryUserDetailsManager(user);
        }
      }
   ```
   3. 第三种方案：自定义实现类
## 授权
### 三个角色判断方法
* hasAuthority
  * 如果当前主体有指定的权限，则返回true，无返回false
* hasAnyAuthority("role1,role2,role3")
### 角色和权限命名规范
* role在数据库中必须以ROLE_开头
* 角色必须大写
* 其他的就是权限了
* 控制类上@Secured({"ROLE_ADMIN"})格式角色，默认不开启，配置类上加@EnableGlobalMethodSecurity(securedEnabled = true) 启动
* 控制类上@PreAuthorize("hasAnyAuthority('auth')")格式权限
* 实体类中不需要映射的属性：Transient转瞬即逝的适用于依赖JPA的, @JsonIgnore
* mybatis-plus忽略某个属性 @TableField(exist = false)
### 权限注解
1. `@Secured({"ROLE_ADMIN"})` 对角色进行校验
2. `@PreAuthorize("hasAnyAuthority('write')")` 对权限进行校验，用在方法前
3. `@PostAuthorize("hasAnyAuthority('write')")` 对权限进行校验，用在方法后
4. `@PreFilter(value = "filterObject.id%2==0")` 方法传入数据过滤
5. `@PostFilter("filterObject.username == 'alisa'")` 方法返回数据过滤 保留username == alisa的数据
## 错误界面
### 401未登录异常，403无权限异常
```java
// 实现 AuthenticationEntryPoint
@Component("customAuthenticationEntryPoint")
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    // 构建自定义的响应体
    RestError re = new RestError(HttpStatus.UNAUTHORIZED.toString(), "Authentication failed");
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    OutputStream responseStream = response.getOutputStream();
    ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(responseStream, re);
    responseStream.flush();
  }
}

// 实现 AccessDeniedHandler
public class CustomAccessDeniedHandler implements AccessDeniedHandler {
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
    // 构建自定义的响应体
    RestError re = new RestError(HttpStatus.FORBIDDEN.toString(), "Access denied");
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    OutputStream responseStream = response.getOutputStream();
    ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(responseStream, re);
    responseStream.flush();
  }
}

// 配置 SecurityConfig
@Configuration
@EnableWebSecurity
public class CustomSecurityConfig {
  @Autowired
  @Qualifier("customAuthenticationEntryPoint")
  AuthenticationEntryPoint authEntryPoint;

  @Autowired
  @Qualifier("customAccessDeniedHandler")
  AccessDeniedHandler accessDeniedHandler;

  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails admin = User.withUsername("admin")
      .password("password")
      .roles("ADMIN")
      .build();
    InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
    userDetailsManager.createUser(admin);
    return userDetailsManager;
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.requestMatchers()
      .antMatchers("/login")
      .and()
      .authorizeRequests()
      .anyRequest()
      .hasRole("ADMIN")
      .and()
      .httpBasic()
      .and()
      .exceptionHandling()
      .authenticationEntryPoint(authEntryPoint)
      .accessDeniedHandler(accessDeniedHandler);
    return http.build();
  }
}

```

* 也可以在配置类中直接设置相关页面
  * ```java
          @Bean
          public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
          return http
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
                  .logout(logout->logout.logoutUrl("/logout").deleteCookies("JSESSIONID").invalidateHttpSession(true).logoutSuccessUrl("/index")) //退出登录接口
                  .exceptionHandling(new Customizer<ExceptionHandlingConfigurer<HttpSecurity>>() {
                      @Override
                      public void customize(ExceptionHandlingConfigurer<HttpSecurity> httpSecurityExceptionHandlingConfigurer) {
                          httpSecurityExceptionHandlingConfigurer.accessDeniedPage("/access-denied2.html");
                      }
                  })
                  .build();

      }
```