package org.example.securtiy_role_and_jwt_1.securityfiles;

import org.example.securtiy_role_and_jwt_1.model.UserLogin;
import org.example.securtiy_role_and_jwt_1.myjpas.UserLoginJpa;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class LoginUserDetailFromDatabase implements UserDetailsService {

    @Autowired
    private UserLoginJpa userLoginJpa;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserLogin user=userLoginJpa.findByUsername(username);
        if(user!=null){
            return new LoginUserPrinciple(user);
        }
        else {
            throw new UsernameNotFoundException(username);

        }

    }

}
