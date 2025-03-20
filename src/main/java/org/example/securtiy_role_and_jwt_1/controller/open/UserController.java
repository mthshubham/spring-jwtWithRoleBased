package org.example.securtiy_role_and_jwt_1.controller.open;

import org.example.securtiy_role_and_jwt_1.model.User;
import org.example.securtiy_role_and_jwt_1.model.UserDetails;
import org.example.securtiy_role_and_jwt_1.model.UserLogin;
import org.example.securtiy_role_and_jwt_1.services.user.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {
    @Autowired
    private UserService userService;

    // ------- Sign  Up ---------------
    @PostMapping("/signup")
    public String signup(@RequestBody User user) {
        userService.signUp(user);
        return "Account Created Successfully";
    }

    @PostMapping("/login")
    public String login(@RequestBody UserLogin userLogin) {
        String msg=userService.verifyUser(userLogin);
        if (Boolean.parseBoolean(msg)) {
            try {
                UserDetails userdetails = userService.profile(userLogin);
                return "Welcome " + userdetails.getFirstName() + " " + userdetails.getLastName();
            } catch (Exception e) {
//                e.printStackTrace();
                return "No profile found";
            }
        }
        else {return msg;}

    }
}
