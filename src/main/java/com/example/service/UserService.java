package com.example.service;

import com.example.entity.Role;
import com.example.repository.UserRepository;
import com.example.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Service
@Transactional
public class UserService implements UserDetailsService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @PersistenceContext
    private EntityManager em;

    @Autowired
    public UserService(UserRepository userRepository, @Lazy BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return findUserByUsername(username).orElseThrow(() -> new UsernameNotFoundException("No such user with username: " + username));
    }

    public Optional<User> findUserByUsername(String username){
        return userRepository.findByUsername(username);
    }

    public Optional<User> findUserByEmail(String email){
        return userRepository.findByEmail(email);
    }

    public List<User> getUsers() {
        return userRepository.findAll();
    }

    public void saveUser(User user) {
        if (findUserByUsername(user.getUsername()).isPresent() || findUserByEmail(user.getUsername()).isPresent()) {
            updateUser(user);
            return;
        }

        user.setRoles(Collections.singleton(em.find(Role.class, 1L)));
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        //user.setPasswordConfirm(bCryptPasswordEncoder.encode(user.getPasswordConfirm()));
        userRepository.save(user);
    }

    public void updateUser(User user) {
        userRepository.save(user);
    }

    public boolean deleteUser(Long id) {
        if (userRepository.findById(id).isPresent()) {
            userRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public void saveResult(User user, double result, String size) {
        switch (size) {
            case "sm" -> {
                if (user.getSmResult() == 0 || user.getSmResult() > result)
                    user.setSmResult(result);
            }
            case "md" -> {
                if (user.getMdResult() == 0 || user.getMdResult() > result)
                    user.setMdResult(result);
            }
            case "lg" -> {
                if (user.getLgResult() == 0 || user.getLgResult() > result)
                    user.setLgResult(result);
            }
        }
    }

    public void deleteAll() {
        userRepository.deleteAll();
    }

    public List<User> userGetList(Long idMin) {
        return em.createQuery("SELECT u FROM User u WHERE u.userId > :paramId", User.class)
                .setParameter("paramId", idMin).getResultList();
    }
}
