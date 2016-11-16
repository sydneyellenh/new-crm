package com.users.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

import java.util.List;

import static com.users.security.Role.ROLE_ADMIN;
import static com.users.security.Role.ROLE_USER;

import com.users.beans.User;
import com.users.repositories.ContactRepository;
import com.users.repositories.UserRepository;

@Service
public class PermissionService {

	@Autowired
	private UserRepository userRepo;
	
	//Step 2 - step 25
	@Autowired
	private ContactRepository contactRepo;
	
	//Step 2 - Step 26
	public long findCurrentUserId() {
		List<User> users = userRepo.findByEmail(getToken().getName());
		return users != null && !users.isEmpty() ? users.get(0).getId() : -1;
	}


	
	private AbstractAuthenticationToken getToken() {
		return (AbstractAuthenticationToken) getContext().getAuthentication();
	}


	public boolean hasRole(Role role) {
		for (GrantedAuthority ga : getToken().getAuthorities()) {
			if (role.toString().equals(ga.getAuthority())) {
				return true;
			}
		}
		return false;
	}

//	public boolean canEditUser(long userId) {
//		long currentUserId = userRepo.findByEmail(getToken().getName()).get(0).getId();
//		return hasRole(ADMIN) || (hasRole(USER) && currentUserId == userId);
//	}

	//Step 2 - Step 27
	public boolean canAccessUser(long userId) {
		return hasRole(ROLE_ADMIN) || (hasRole(ROLE_USER) && findCurrentUserId() == userId);
	}
	
	//Step 2 - step 28
	public boolean canEditContact(long contactId) {
		return hasRole(ROLE_USER) && contactRepo.findByUserIdAndId(findCurrentUserId(), contactId) != null;
	}

	public String getCurrentEmail() {
		return getToken().getName();
	}

	public User findCurrentUser() {
		List<User> users = userRepo.findByEmail(getToken().getName());
		return users != null && !users.isEmpty() ? users.get(0) : new User();
	}

	
}
