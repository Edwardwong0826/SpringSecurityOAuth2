package com.wongweiye.security.service;


import com.wongweiye.model.User;
import com.wongweiye.repository.NoteRepository;
import com.wongweiye.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

// refer to this https://stackoverflow.com/questions/51712724/how-to-allow-a-user-only-access-their-own-data-in-spring-boot-spring-security
// https://spring.io/guides/topicals/spring-security-architecture/ - for the Authentication and Access Control
@Component
public class UserSecurity implements AuthorizationManager<RequestAuthorizationContext> {

    @Autowired
    UserRepository userRepository;

    @Autowired
    NoteRepository noteRepository;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, RequestAuthorizationContext ctx) {

        String userName = String.valueOf(ctx.getVariables().get("userName"));
        String title = String.valueOf(ctx.getVariables().get("title"));
        Authentication authentication = (Authentication) authenticationSupplier.get();

        AuthorizationDecision authorizationDecision;
        if(!title.equals("null")){
            authorizationDecision = new AuthorizationDecision(checkNoteUserName(authentication, userName, title));
        }
        else {
            authorizationDecision = new AuthorizationDecision(checkUserName(authentication, userName));
        }

        return authorizationDecision;
    }

    public boolean checkNoteUserName(Authentication authentication, String userName, String title) {

        User principalUser = userRepository.findFirstByUsername(authentication.getName());
        String principalUserName = principalUser.getUsername();

        return authentication.getName().equals(principalUserName) && userName.equals(principalUserName);

    }

    public boolean checkUserName(Authentication authentication, String userName){

        User user = userRepository.findFirstByUsername(authentication.getName());
        String username = user.getUsername();

        return authentication.getName().equals(username) && userName.equals(username);
    }

}
