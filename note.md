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
