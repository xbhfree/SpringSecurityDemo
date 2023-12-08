package com.example.springsecuritydemo.pojo;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.example.springsecuritydemo.mapper.RoleMapper;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@TableName("t_user")
@Data
public class User implements UserDetails {
    private Integer id;

    private String username;

    private String password;

    private  boolean accountNonExpired;
    private  boolean accountNonLocked;
    private  boolean credentialsNonExpired;
    private  boolean enabled;

    //忽略映射
    @TableField(exist = false)
    private List<Role> roles;

    @TableField(exist = false)
    private List<Permission> permissions;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
        //getAuthorities() 方法是 UserDetails 接口中的一个方法，用于返回用户的权限信息。
        //在Spring Security中，这个方法在用户认证成功后、用于授权访问资源时被调用。
        if (this.roles != null){
            this.roles.forEach(role -> grantedAuthorityList.add(new SimpleGrantedAuthority(role.getRoleName())));
        }
        if (this.permissions != null){
            this.permissions.forEach(p -> grantedAuthorityList.add(new SimpleGrantedAuthority(p.getPermName())));
        }
        return grantedAuthorityList;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    //默认为false，即为上锁
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
