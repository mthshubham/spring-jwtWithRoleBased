package org.example.securtiy_role_and_jwt_1.myjpas;

import org.example.securtiy_role_and_jwt_1.model.UserDetails;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDetailJpa extends JpaRepository<UserDetails,Long> {
    UserDetails findById(long id);
}
