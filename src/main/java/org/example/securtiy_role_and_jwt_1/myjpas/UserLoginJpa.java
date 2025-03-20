package org.example.securtiy_role_and_jwt_1.myjpas;

import org.example.securtiy_role_and_jwt_1.model.UserLogin;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;


public interface UserLoginJpa extends JpaRepository<UserLogin,Long> {
    UserLogin findByUsername(String username);
    @Query(value = "SELECT user_detail_id FROM user_login WHERE username = :username", nativeQuery = true)
    Long findUserLoginIdByUserDetailsId(@Param("username") String username);

}
