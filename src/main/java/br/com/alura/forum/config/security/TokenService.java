package br.com.alura.forum.config.security;

import java.util.Date;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class TokenService {
	
	@Value("${forum.jwt.secret}")
	private String secretKey = "uWTkyc2DQf9aOQ7V_ufL0O6MEmC08k4WaD1qGqD75O2y30_BSDhjCidWR3aAmcliDySl5RvbLcjeuSW8qQXI6w";
	
	@Value("${forum.jwt.expiration}")
	private Long expiration;
	
	public String gerarToken(Authentication authentication) {
		
		Usuario usuario = (Usuario) authentication.getPrincipal();
		
		Date dataAtual = new Date();
		Date dataExpiracao = new Date(dataAtual.getTime() + expiration);
		
		return Jwts.builder()
			.setIssuer("Forum API")
			.setIssuedAt(dataAtual)
			.setSubject(usuario.getId().toString())
			.setExpiration(dataExpiracao)
			.signWith(SignatureAlgorithm.HS512, secretKey).compact();
	}
	
	
	public static void main(String[] args) {
		StringBuilder key = new StringBuilder();
		for(int i = 0; i < 10; i ++) {
			key.append(UUID.randomUUID().toString().replace("-", "") + "-");
		}
		
		System.out.println(key.toString());
	}


	public boolean isValid(String token) {
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
	}


	public Long recuperarIdUsuario(String token) {
		Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
		
		Long idUsuario = Long.parseLong(claims.getSubject());
		
		return idUsuario;
	}
	
	

}
