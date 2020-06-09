package br.com.alura.forum.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.alura.forum.config.security.TokenService;
import br.com.alura.forum.controller.dto.AuthResponseDTO;
import br.com.alura.forum.controller.form.LoginForm;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiModelProperty;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@RequestMapping("/auth")
@Api(value = "API para autenticação de usuários", tags = "Autenticação", description = "Operações para autenticação")
public class AutenticacaoController {
	
	@Autowired
	private TokenService tokenService;
	
	@Autowired
	private AuthenticationManager authManager;
	
	private static final String BEARER = "Bearer";
	
	@ApiResponses(value = {
		    @ApiResponse(code = 200, message = "Retorna uma lista com o resultado"),
		    @ApiResponse(code = 403, message = "Você não tem permissão para acessar este recurso"),
		    @ApiResponse(code = 500, message = "Ocorreu um erro interno"),
		})
	@PostMapping
	@ApiOperation(value = "Autenticação básica", produces = "Application/Json")
	public ResponseEntity<?> autenticar(@RequestBody @Valid LoginForm loginForm) {
		
		UsernamePasswordAuthenticationToken dadosLogin = loginForm.converter();
		
		try {
			
			Authentication authentication = authManager.authenticate(dadosLogin);
			String token = tokenService.gerarToken(authentication);
			
			AuthResponseDTO response = new AuthResponseDTO();
			response.setAccess_token(token);
			response.setType(BEARER);
			return ResponseEntity.ok(response);
		} catch (UsernameNotFoundException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
		}
		
	}

}
