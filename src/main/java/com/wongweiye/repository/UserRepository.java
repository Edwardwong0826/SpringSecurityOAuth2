package com.wongweiye.repository;


import com.wongweiye.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findFirstByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}

