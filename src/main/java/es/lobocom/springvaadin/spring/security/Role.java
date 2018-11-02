package es.lobocom.springvaadin.spring.security;

public class Role {
	public static final String USUARIO = "usuario";
	public static final String ADMIN = "admin";

	private Role() {
		// Static methods and fields only
	}

	public static String[] getAllRoles() {
		return new String[] { USUARIO, ADMIN };
	}

}
