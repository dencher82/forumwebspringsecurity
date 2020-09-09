package telran.ashkelon2020.accounting.security.service;

import java.io.IOException;
import java.security.Principal;
import java.time.LocalDateTime;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.GenericFilterBean;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.model.User;

@Service
public class ExpDateFilter extends GenericFilterBean {

	@Autowired
	UserRepositoryMongoDB accountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String path = request.getServletPath();
		String method = request.getMethod();
		Principal principal = request.getUserPrincipal();
		if (checkPathAndMethod(path, method)) {
			User user = accountRepository.findById(principal.getName()).get();
			if (LocalDateTime.now().isAfter(user.getExpDate())) {
				response.sendError(403, "Password expired");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPathAndMethod(String path, String method) {
		boolean res = "/account/login".equalsIgnoreCase(path) && "Post".equalsIgnoreCase(method);
		res = res || ("Put".equalsIgnoreCase(method) && path.matches("/account/user/\\w+/?"));
		boolean forum = path.startsWith("/forum") && (!"GET".equalsIgnoreCase(method))
				&& (!path.matches("/forum/posts/(tags|period)/?"));
		res = res || forum;
		return res;
	}

}