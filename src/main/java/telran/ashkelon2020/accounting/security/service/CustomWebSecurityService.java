package telran.ashkelon2020.accounting.security.service;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;
import telran.ashkelon2020.forum.dao.ForumRepositoryMongoDB;
import telran.ashkelon2020.forum.model.Post;

@Service("customSecurity")
public class CustomWebSecurityService {

	@Autowired
	ForumRepositoryMongoDB forumRepository;
	
	@Autowired
	UserRepositoryMongoDB userRepository;

	public boolean checkPostAuthority(String id, String user) {
		Post post = forumRepository.findById(id).orElse(null);
		return post == null ? true : post.getAuthor().equals(user); // pass throw Spring Security and service will check
																	// if post exists or not
	}
	
	public boolean checkExpDate(String login) {
		User user = userRepository.findById(login).orElse(null);
		return user == null ? true : user.getExpDate().isAfter(LocalDateTime.now());
		
	}

}
