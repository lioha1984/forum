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

@Component
@RequiredArgsConstructor
@Order(40)
public class AuthorLoginFilter implements Filter {

	final UserAccountRepository userAccountRepository;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String[] arr = request.getServletPath().split("/");

			if (request.getUserPrincipal().getName().compareTo(arr[arr.length - 1]) != 0) {
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return (("POST".compareTo(method.toUpperCase()) == 0 && servletPath.matches("/forum/post/\\w+/?")) ||
				("PUT".compareTo(method.toUpperCase()) == 0 && servletPath.matches("/forum/post/\\w+/comment/\\w+/?"))); 
			
	}

}
