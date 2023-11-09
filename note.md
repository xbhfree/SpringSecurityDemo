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