package com.example.Keycloak;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Controller
public class HomeController {

    String i = "1";

    @GetMapping("/index")
    public String homepage(){
            return "index";
    }

    @GetMapping("/login")
    public String loginpage(){
        i = i + "1";
        return i;
    }

    @GetMapping("/")
    public String homepage2(){
        return "index";
    }

    @GetMapping("/welcome")
    public String welcome(){
        return "welcome";
    }

    @GetMapping("/hello-admin")
    @PreAuthorize("hasRole('client_manager')")
    public String helloadmin(){

        return "hello-admin";
    }

    @GetMapping("/hello")
    //@PreAuthorize("hasRole('client_user')")
    public String hello_user(){
        return "hello";
    }


    /*@GetMapping("/hello")
    @PreAuthorize("isAuthenticated()")
    public String hello(){
        return "hello";
    }*/

    /*@RequestMapping("/logout")
    public String logout(){
        return "0";
    }*/
}
