package telran.ashkelon2020.accounting.service;

import java.time.LocalDateTime;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.dto.UserRegisterDto;
import telran.ashkelon2020.accounting.dto.UserResponseDto;
import telran.ashkelon2020.accounting.dto.UserUpdateDto;
import telran.ashkelon2020.accounting.dto.exception.UserExistsException;
import telran.ashkelon2020.accounting.dto.exception.UserNotFoundException;
import telran.ashkelon2020.accounting.model.User;

@Component
@ManagedResource
public class UserServiceImpl implements UserService {

	@Autowired
	UserRepositoryMongoDB repository;
	
	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	ModelMapper modelMapper;

	@Value("${expdate.value}")
	private long period;

	@Value("${default.role}")
	private String defaultUser;
	
	@ManagedAttribute // can see this attribute in Runtime (jconsole)
	public long getPeriod() {
		return period;
	}
	
	@ManagedAttribute // can change this attribute in Runtime (jconsole)
	public void setPeriod(long period) {
		this.period = period;
	}

	public String getDefaultUser() {
		return defaultUser;
	}

	public void setDefaultUser(String defaultUser) {
		this.defaultUser = defaultUser;
	}

	@Override
	public UserResponseDto addUser(UserRegisterDto userRegisterDto) {
		if (repository.existsById(userRegisterDto.getLogin())) {
			throw new UserExistsException(userRegisterDto.getLogin());
		}
		String hashPassword = passwordEncoder.encode(userRegisterDto.getPassword()); // encode password with Spring Security
		User user = modelMapper.map(userRegisterDto, User.class);
		user.setPassword(hashPassword);
		user.setExpDate(LocalDateTime.now().plusDays(period));
		user.addRole(defaultUser.toUpperCase());
		userRegisterDto.getRoles().forEach((r) -> user.addRole(r.toString()));
		repository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}
	
	@Override
	public UserResponseDto findUserByLogin(String login) {
		User user = repository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto deleteUser(String login) {
		User user = repository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		repository.deleteById(login);
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto updateUser(String login, UserUpdateDto userUpdateDto) {
		User user = repository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		if (userUpdateDto.getFirstName() != null) {
			user.setFirstName(userUpdateDto.getFirstName());
		}
		if (userUpdateDto.getLastName() != null) {
			user.setLastName(userUpdateDto.getLastName());
		}
		repository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}

	@Override
	public UserResponseDto changeRolesList(String login, String role, boolean isAddRole) {
		User user = repository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		boolean res;
		if (isAddRole) {
			res = user.addRole(role);
		} else {
			res = user.removeRole(role);
		}
		if (res) {
			repository.save(user);
		}
		return modelMapper.map(user, UserResponseDto.class);
	}
	
	@Override
	public UserResponseDto changeUserPassword(String login, String newPassword) {
		User user = repository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		String hashPassword = passwordEncoder.encode(newPassword);  // encode password with Spring Security
		user.setPassword(hashPassword);
		user.setExpDate(LocalDateTime.now().plusDays(period));
		repository.save(user);
		return modelMapper.map(user, UserResponseDto.class);
	}	

}
