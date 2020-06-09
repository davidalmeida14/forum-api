package br.com.alura.forum.controller.dto;

public class AuthResponseDTO {
	
	private String access_token;
	
	private String type;

	public String getAccess_token() {
		return access_token;
	}

	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
	
	
	

}
