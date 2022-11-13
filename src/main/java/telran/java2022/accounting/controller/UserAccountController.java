package telran.java2022.accounting.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dto.RolesResponseDto;
import telran.java2022.accounting.dto.UserAccountResponseDto;
import telran.java2022.accounting.dto.UserRegisterDto;
import telran.java2022.accounting.dto.UserUpdateDto;
import telran.java2022.accounting.service.UserAccountService;

@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class UserAccountController {

	final UserAccountService accountService;

	@PostMapping("/register")
	public UserAccountResponseDto register(@RequestBody UserRegisterDto userRegisterDto) {
		return accountService.addUser(userRegisterDto);
	}

	@PostMapping("/login")
	public UserAccountResponseDto login(Principal principal) {
		return accountService.getUser(principal.getName());
	}

	@DeleteMapping("/user/{login}")
	public UserAccountResponseDto removeUser(Principal principal) {
		return accountService.removeUser(principal.getName());
	}

	@PutMapping("/user/{login}")
	public UserAccountResponseDto updateUser(Principal principal, @RequestBody UserUpdateDto userUpdateDto) {
		return accountService.editUser(principal.getName(), userUpdateDto);
	}

	@PutMapping("/user/{login}/role/{role}")
	public RolesResponseDto addRole(@PathVariable String login, @PathVariable String role) {
		return accountService.changeRolesList(login, role, true);
	}

	@DeleteMapping("/user/{login}/role/{role}")
	public RolesResponseDto removeRole(@PathVariable String login, @PathVariable String role) {
		return accountService.changeRolesList(login, role, false);
	}

	@PutMapping("/password")
	public void changePassword(Principal principal, @RequestHeader("X-Password") String newPassword) {
		accountService.changePassword(principal.getName(), newPassword);
	}

}
