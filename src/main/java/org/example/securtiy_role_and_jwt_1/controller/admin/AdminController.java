package org.example.securtiy_role_and_jwt_1.controller.admin;

import org.example.securtiy_role_and_jwt_1.model.UserDetails;
import org.example.securtiy_role_and_jwt_1.services.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/admin")
public class AdminController {


    @Autowired
    private UserService userService;

    @GetMapping("/")
    public String adminLogin(){return "admin login success";}

    @GetMapping("/allusers")   /* ------------ Show all User  */
    public List<UserDetails> showAllUsers(){
        List<UserDetails> mylist=userService.showAllUsers();
        if(!mylist.isEmpty()){
            return mylist;
        }
        return null;
    }
}
