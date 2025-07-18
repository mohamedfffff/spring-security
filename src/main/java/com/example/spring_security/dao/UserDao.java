package com.example.spring_security.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Repository
public class UserDao {

    static BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    static String  encoded = encoder.encode("password");
    private final static String password = encoded;
    //creating a static list of users to use in auth without database
    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "hdtsfr84@gmail.com",
                    password,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))
            ),
            new User(
                    "wazagachan@gmail.com",
                    password,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
            ),
            new User(
                    "scar@gmail.com",
                    password,
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
            )
    );

    public UserDetails findUserByEmail(String email){
        return APPLICATION_USERS
                .stream()
                .filter(u -> u.getUsername().equals(email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("user not found"));
    }
}
