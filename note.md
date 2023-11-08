# 基础
## 基本原理
* spring security本质是过滤器链
  * FilterSecurityInterceptor  方法级过滤器，基本位于过滤链最底层
  * ExceptionTranslationFilter 异常过滤器，处理授权过程中抛出的异常
  * UsernamePasswordAuthenticationFilter 用户登录认证过滤器
