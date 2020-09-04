package telran.ashkelon2020;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;

@SpringBootApplication
public class ForumServiceSpringSecurityApplication implements CommandLineRunner{

	@Autowired
	UserRepositoryMongoDB userRepository;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	public static void main(String[] args) {
		SpringApplication.run(ForumServiceSpringSecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		if (!userRepository.existsById("admin")) {
			String hashPassword = passwordEncoder.encode("admin");
			User admin = new User();
			admin.setLogin("admin");
			admin.setPassword(hashPassword);
			admin.getRoles().add("ADMIN");
			admin.getRoles().add("MODERATOR");
			admin.getRoles().add("USER");
			admin.setExpDate(LocalDateTime.now().plusYears(25));
			admin.setFirstName("Administrator");
			admin.setLastName("Administrator");
			userRepository.save(admin);
		}
	}

}
