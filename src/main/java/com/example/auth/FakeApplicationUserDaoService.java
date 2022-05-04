package com.example.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.security.ApplicationUserRole.*;

@Repository("Fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
    return getApplicationUsers().stream()
        .filter(applicationUser -> applicationUser.getUsername().equals(username))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUsers() {
    List<ApplicationUser> applicationUsers =
        Lists.newArrayList(
            new ApplicationUser(
                "anna",
                passwordEncoder.encode("pass"),
                STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true),
            new ApplicationUser(
                "tom",
                passwordEncoder.encode("pass"),
                ADMINTRAINEE.getGrantedAuthorities(),
                true,
                true,
                true,
                true),
            new ApplicationUser(
                "linda",
                passwordEncoder.encode("pass"),
                ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true));

    return applicationUsers;
  }
}
