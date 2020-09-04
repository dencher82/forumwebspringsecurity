package telran.ashkelon2020.accounting.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import telran.ashkelon2020.accounting.dto.UserRegisterDto;
import telran.ashkelon2020.accounting.dto.UserResponseDto;
import telran.ashkelon2020.accounting.dto.UserUpdateDto;
import telran.ashkelon2020.accounting.service.UserService;

@RestController
@RequestMapping("/account")
public class UserController {

	@Autowired
	UserService userService;
	
	@PostMapping("/register")
	public UserResponseDto register(@RequestBody UserRegisterDto userRegisterDto) {
		return userService.addUser(userRegisterDto);
	}

	@PostMapping("/login")
	public UserResponseDto login(Authentication authentication) {
		return userService.findUserByLogin(authentication.getName());
	}

	@PutMapping("/user/{login}")
	public UserResponseDto updateUser(@PathVariable String login, @RequestBody UserUpdateDto userUpdateDto) {
		return userService.updateUser(login, userUpdateDto);
	}

	@DeleteMapping("/user/{login}")
	public UserResponseDto deleteUser(@PathVariable String login) {
		return userService.deleteUser(login);
	}
	
	@PutMapping("/user/{login}/role/{role}")
	public UserResponseDto addRole(@PathVariable String login, @PathVariable String role) {
		return userService.changeRolesList(login, role, true);
	}

	@DeleteMapping("/user/{login}/role/{role}")
	public UserResponseDto deleteRole(@PathVariable String login, @PathVariable String role) {
		return userService.changeRolesList(login, role, false);
	}

	@PutMapping("/password")
	public UserResponseDto changeUserPassword(@RequestHeader("X-Password") String password, Authentication authentication) {
		return userService.changeUserPassword(authentication.getName(), password);
	}

}
