package telran.java2022.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.dto.exceptions.PostNotFoundException;
import telran.java2022.post.model.Post;

@Component
@RequiredArgsConstructor
@Order(50)
public class DeleteUpdatePostFilter implements Filter {

	final PostRepository postRepository;
	final UserAccountRepository userAccountRepository;
	
	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getServletPath())) {
			String[] arr = request.getServletPath().split("/");

			Post post = postRepository.findById(arr[arr.length - 1]).orElseThrow(() -> new PostNotFoundException(arr[arr.length - 1]));
			UserAccount userAccount = userAccountRepository.findById(request.getUserPrincipal().getName()).get();
			
			
			if ("DELETE".compareTo(request.getMethod().toUpperCase()) == 0) {
				if (!(userAccount.getLogin().compareTo(post.getAuthor()) == 0 || 
					  userAccount.getRoles().contains("MODERATOR"))) {
					response.sendError(403);
					return;
				}
			} else if ("PUT".compareTo(request.getMethod().toUpperCase()) == 0) {
				if (userAccount.getLogin().compareTo(post.getAuthor()) != 0) {
					response.sendError(403);
					return;
				}
			} else {
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String servletPath) {
		return servletPath.matches("/forum/post/\\w+/?");
	}

}
