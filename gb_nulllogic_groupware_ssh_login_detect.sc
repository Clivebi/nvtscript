if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800904" );
	script_version( "2021-07-19T10:51:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 10:51:38 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "NullLogic Groupware Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of NullLogic Groupware." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/(nullgw-)?dbutil$", useregex: TRUE, sock: sock );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
for bin in paths {
	vers = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-V", ver_pattern: "NullLogic Groupware ([0-9.]+)" );
	if(vers[1]){
		version = vers[1];
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:nulllogic:groupware:" );
		if(!cpe){
			cpe = "cpe:/a:nulllogic:groupware";
		}
		register_product( cpe: cpe, location: bin, port: 0, service: "ssh-login" );
		log_message( data: build_detection_report( app: "NullLogic Groupware", version: version, install: bin, cpe: cpe, concluded: vers[0] ), port: 0 );
	}
}
ssh_close_connection();
exit( 0 );

