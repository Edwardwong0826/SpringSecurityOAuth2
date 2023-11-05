package com.wongweiye.security.service;


import com.wongweiye.model.User;
import com.wongweiye.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// By default, AuthenticationManager(ProviderManager) will use DaoAuthenticationProvider
// DaoAuthenticationProvider by invoke UserDetailsService retrieveUser, retrieveUser method call this.getUserDetailsService().loadUserByUsername(username)
// to return UserDetails and do authenticate, if UserDetails not null then success authenticate else failed authenticate
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    // UserDetailsService is the interface that do the user source authentication by spring security
    // in our case, we create the username and password stored into database table, so we create our own class
    // to implement and override UserDetailsService loadUserByUsername method to return userDetails, therefore AuthenticationProvider
    // will choose our class to get the username instead of use default InMemoryUserDetailsManager to get
    // UserDetailsServiceAutoConfiguration will decide by spring boot autoconfigure which implementation to use in spring security
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findFirstByUsername(username);

        return UserDetailsImpl.build(user);
    }
}
