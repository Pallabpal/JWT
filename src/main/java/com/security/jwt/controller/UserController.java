package com.security.jwt.controller;

import com.security.jwt.entity.AuthRequest;
import com.security.jwt.entity.UserInfo;
import com.security.jwt.service.JwtService;
import com.security.jwt.service.UserInfoService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

@RestController
@RequestMapping("/auth")
@Slf4j
public class UserController {

    @Autowired
    UserInfoService userInfoService;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtService jwtService;

    @GetMapping("/welcome")
    public String welcome(){
        return "welcome";
    }

    @PostMapping("/adduser")
    public String addUser(@RequestBody UserInfo userInfo){

        return userInfoService.addUser(userInfo);

    }




    @PostMapping("/login")
    public String login(@RequestBody AuthRequest authRequest){

        Authentication authentication= authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUserName(),authRequest.getPassword()));

        if(authentication.isAuthenticated()){
            return jwtService.generateToken(authRequest.getUserName());
        }
        else{
            throw new UsernameNotFoundException("Invalid User Request");
        }

    }

    @GetMapping("/getusers")
    public List<UserInfo> getAllUser(){
        Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        if(authentication1==null)
            log.info("the value is null");
        else
            log.info("the user "+authentication1.getName());
        return userInfoService.getAllUser();
    }

    @GetMapping("/getusers/{id}")
    public UserInfo getAllUser(@PathVariable Integer id){
       return userInfoService.getUser(id);
    }

}
