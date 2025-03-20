package org.example.securtiy_role_and_jwt_1.myjpas;

import org.example.securtiy_role_and_jwt_1.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleJpa extends JpaRepository<Role,Long> {
}
