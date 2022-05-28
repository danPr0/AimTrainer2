package com.example.entity;

import com.example.model.AuthProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

@Entity
@Table(name = "users")
public class User implements UserDetails {
    @Id
//    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "users_seq")
//    @SequenceGenerator(name = "users_seq", sequenceName = "SEQ_USER",
//            initialValue = 5, allocationSize = 5)
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private long userId;

    @Column(name = "username")
    private String username;

    @Column(name = "email")
    private String email;

    @Column(name = "sm_result")
    private double smResult = 0;

    @Column(name = "md_result")
    private double mdResult = 0;

    @Column(name = "lg_result")
    private double lgResult = 0;

    @Column(name = "password")
    private String password;

    @Column(name = "provider")
    private String provider;

    @Column(name = "enabled")
    private boolean enabled = false;

    @Column(name = "created_at")
    private Date createdAt;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable (name="user_role",
            joinColumns=@JoinColumn (name="user_id"),
            inverseJoinColumns=@JoinColumn(name="role_id"))
    private Set<Role> roles;

    public User() {}

    public User(String username, String email, String password){
        setUsername(username);
        setEmail(email);
        setPassword(password);
    }

    public Long getId() {
        return userId;
    }

    public void setId(Long userId) {
        this.userId = userId;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

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
        return enabled;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return getRoles();
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + username + '\'' +
                ", id='" + userId + '\'' +
                '}';
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public AuthProvider getProvider() {
        return AuthProvider.valueOf(provider);
    }

    public void setProvider(AuthProvider provider) {
        this.provider = provider.name();
    }

    public double getSmResult() {
        return smResult;
    }

    public void setSmResult(double smResult) {
        this.smResult = smResult;
    }

    public double getMdResult() {
        return mdResult;
    }

    public void setMdResult(double mdResult) {
        this.mdResult = mdResult;
    }

    public double getLgResult() {
        return lgResult;
    }

    public void setLgResult(double lgResult) {
        this.lgResult = lgResult;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }
}