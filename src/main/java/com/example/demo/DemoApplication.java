package com.example.demo;

import com.example.demo.domain.Role;
import com.example.demo.domain.User;
import com.example.demo.services.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
@Slf4j
@SpringBootApplication
public class DemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

//	@Bean
//	PasswordEncoder passwordEncoder(){
//		log.error("PasswordEncoder");
//		return new BCryptPasswordEncoder();
//	}

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		log.error("BcryptPasswordEncoder");
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		log.error("Testing CommandLineRunner");
		return args -> {
			userService.saveRole(new Role(null,"ROLE_USER"));
			userService.saveRole(new Role(null,"ROLE_MANAGER"));
			userService.saveRole(new Role(null,"ROLE_ADMIN"));
			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));

			User johnDoe = User.builder().name("John Doe").username("john").password("1234")
					.roles(new ArrayList<>()).build();
			User willSmith = User.builder().name("Will Smith").username("will").password("1234")
					.roles(new ArrayList<>()).build();
			User jimCarry = User.builder().name("Jim Carry").username("jim").password("1234")
					.roles(new ArrayList<>()).build();
			User sandraBullock = User.builder().name("Johnny Dep").username("johny").password("1234")
					.roles(new ArrayList<>()).build();
			userService.saveUser(johnDoe);
			userService.saveUser(willSmith);
			userService.saveUser(jimCarry);
			userService.saveUser(sandraBullock);

			userService.addRoleToUser("john","ROLE_USER");
			userService.addRoleToUser("john","ROLE_MANAGER");
			userService.addRoleToUser("will","ROLE_MANAGER");
			userService.addRoleToUser("jim","ROLE_ADMIN");
			userService.addRoleToUser("johny","ROLE_SUPER_ADMIN");
			userService.addRoleToUser("johny","ROLE_ADMIN");
			userService.addRoleToUser("johny","ROLE_USER");
		};
	}
}
