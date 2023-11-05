package com.wongweiye.controller;


import com.wongweiye.model.ERole;
import com.wongweiye.model.Role;
import com.wongweiye.model.User;
import com.wongweiye.payload.request.LoginRequest;
import com.wongweiye.payload.request.SignupRequest;
import com.wongweiye.payload.response.JwtResponse;
import com.wongweiye.payload.response.MessageResponse;
import com.wongweiye.repository.RoleRepository;
import com.wongweiye.repository.UserRepository;
import com.wongweiye.security.service.JwtUtils;
import com.wongweiye.security.service.UserDetailsImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    // we are using our own data source way to authenticate
    // SecurityContextHolder will store authentication object, it was used to retrieve after login user information
    // spring security will store user information to session, by using ThreadLocal to store, so that only current
    // request thread can access the user information
    // SecurityContextHolder 用来获取登录之后用户信息。Spring Security 会将登录用户数据保存在 Session 中。但是，为了使用方便,Spring Security在此基础上还做了一些改进，
    // 其中最主要的一个变化就是线程绑定。当用户登录成功后,Spring Security 会将登录成功的用户信息保存到 SecurityContextHolder 中。SecurityContextHolder 中的数据保存默认是通过ThreadLocal 来实现的，
    // 使用 ThreadLocal 创建的变量只能被当前线程访问，不能被其他线程访问和修改，也就是用户数据和请求线程绑定在一起。当登录请求处理完毕后，Spring Security 会将 SecurityContextHolder
    // 中的数据拿出来保存到 Session 中，同时将 SecurityContextHolder 中的数据清空。以后每当有请求到来时，Spring Security 就会先从 Session 中取出用户登录数据，保存到 SecurityContextHolder 中，
    // 方便在该请求的后续处理过程中使用，同时在请求结束时将 SecurityContextHolder 中的数据拿出来保存到 Session 中，然后将 Security SecurityContextHolder 中的数据清空。
    // 这一策略非常方便用户在 Controller、Service 层以及任何代码中获取当前登录用户数据。
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        // AuthenticationManager is only one that will do authenticate, it requires Authentication and if success it will return complete Authentication else failed will return null or others
        // default implementation of AuthenticationManager is ProviderManager
        // Authentication instance will contain information like Principal(user information), Authorities(permission),
        // Credentials(password, secret etc. but this Credentials info will erase by spring security therefore we can't get
        // UsernamePasswordAuthenticationToken is a AbstractAuthenticationToken and is inherited Authentication

        // There is GrantedAuthority Collection stored login user permission info
        // Spring Security provide two policy to manage access control
        // 1 based on filter way - FilterSecurityInterceptor, before http request reach method
        // 2 based on AOP way - MethodSecurityInterceptor, after http request invoke method
        Authentication authentication  = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        // SecurityContextHolder use Strategy to determine which context to use
        // ThreadLocalSecurityContextHolderStrategy - for current thread to use only
        // InheritableThreadLocalSecurityContextHolderStrategy - for current thread and its child thread to use as well
        // GlobalSecurityContextHolderStrategy - save the data into static variable, rarely use
        // SecurityContext interface got two methods - getAuthentication and setAuthentication
        // when we use our way and success authenticate, then we use setAuthentication pass Authentication to securityContext to indicate spring security that is authenticated already
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map( grantedAuthority -> grantedAuthority.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "mod":
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

}
