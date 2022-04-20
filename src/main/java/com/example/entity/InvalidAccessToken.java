package com.example.entity;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "invalid_access_tokens")
public class InvalidAccessToken {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @Column(name = "username")
    private String username;

    @Column(name = "token")
    private String token;

    @Column(name = "expiration")
    private Date expiration;

    public InvalidAccessToken() {}

    public InvalidAccessToken(String username, String token, Date expiration) {
        this.username = username;
        this.token = token;
        this.expiration = expiration;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public Date getExpiration() {
        return expiration;
    }

    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }
}
