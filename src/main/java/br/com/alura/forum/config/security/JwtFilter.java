package br.com.alura.forum.config.security;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

@Component
public class JwtFilter extends OncePerRequestFilter {
	
	private TokenService tokenService;
	private UsuarioRepository usuarioRepository;
	
	public JwtFilter(TokenService tokenService, UsuarioRepository usuarioRepository) {
		this.tokenService = tokenService;
		this.usuarioRepository = usuarioRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		
		String token = request.getHeader("Authorization");
		
		if(Objects.nonNull(token) && token.startsWith("Bearer")) {
			token = token.substring(7);
			
			boolean valido = tokenService.isValid(token);
			
			if(valido) {
				Long id = tokenService.recuperarIdUsuario(token);
				Usuario usuario = usuarioRepository.findById(id).get();
				UsernamePasswordAuthenticationToken authentication = recuperarUserToken(usuario);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		chain.doFilter(request, response);
		
	}

	private UsernamePasswordAuthenticationToken recuperarUserToken(Usuario usuario) {
		return new UsernamePasswordAuthenticationToken(usuario.getEmail(), null, usuario.getAuthorities());
	}

}
