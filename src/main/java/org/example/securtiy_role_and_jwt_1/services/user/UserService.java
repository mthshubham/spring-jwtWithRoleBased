package org.example.securtiy_role_and_jwt_1.services.user;



import org.example.securtiy_role_and_jwt_1.model.*;
import org.example.securtiy_role_and_jwt_1.myjpas.RoleJpa;
import org.example.securtiy_role_and_jwt_1.myjpas.UserDetailJpa;
import org.example.securtiy_role_and_jwt_1.myjpas.UserLoginJpa;
import org.example.securtiy_role_and_jwt_1.services.jwtServices.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {

    @Autowired
    private UserLoginJpa loginJpa;
    @Autowired
    private UserDetailJpa detailJpa;
    @Autowired
    private RoleJpa roleJpa;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtService jwtService;
    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);




    // ------------------  Sign-up  --------------------------
    public UserLogin signUp(User user){

        UserDetails userDetails = new UserDetails();
        UserLogin userLogin = new UserLogin();
        Role role = new Role();

        {// user Detail saving
            userDetails.setFirstName(user.getFirstName());
            userDetails.setLastName(user.getLastName());
            userDetails.setEmail(user.getEmail());
            userDetails.setGender(user.getGender());
            userDetails.setPhoneNumber(user.getPhoneNumber());
            userDetails.setCountry(user.getCountry());
            userDetails.setCity(user.getCity());
            userDetails.setState(user.getState());
            userDetails.setZip(user.getZip());
            userDetails.setLocalAddress(user.getLocalAddress());
            detailJpa.save(userDetails);
        }

        {

            role.setRoleName("ROLE_ADMIN");
            roleJpa.save(role);
        }
        {// user login data saving
            userLogin.setPassword(encoder.encode(user.getPassword()));
            userLogin.setUsername(user.getUsername());

            userLogin.setUserDetails(userDetails);
            userLogin.setRoles(Set.of(role));
            loginJpa.save(userLogin);
        }
        return new UserLogin();
    }


// -----------------------------Show all ----------------------------------
    public List<UserDetails> showAllUsers(){
        return detailJpa.findAll();
    }
//    Verify User
    public String verifyUser(UserLogin user){
        if(loginJpa.findByUsername(user.getUsername())!=null){
            try{
                Authentication authentication=authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
                );
                try {
                    if (authentication.isAuthenticated()){
                        System.out.println(1);
                        String secret=jwtService.generateToken(user.getUsername());
                        System.err.println(secret);
                    }
                }catch (Exception e){
                    e.printStackTrace();
                    return "Token creation failed";}

                return String.valueOf(authentication.isAuthenticated());
            }catch (Exception e){
                return "Invalid Password";
            }
        }
        return "Invalid Username";
    }

//  find by username
    public UserLogin findUserByUsername(String username){
        return loginJpa.findByUsername(username);
    }

//    profile getting
    public UserDetails profile(UserLogin user){
        user=loginJpa.findByUsername(user.getUsername());
        Long id= loginJpa.findUserLoginIdByUserDetailsId(user.getUsername());
        Optional<UserDetails> details=detailJpa.findById(id);
        return details.get();

    }
}
