package org.example.securtiy_role_and_jwt_1.controller.open;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Test {

    @GetMapping
    public String test(){
        return " -- ok from securtiy_role_and_jwt_1";
    }

}
