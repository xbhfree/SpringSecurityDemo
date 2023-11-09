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
    
