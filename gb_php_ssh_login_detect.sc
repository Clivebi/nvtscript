if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103592" );
	script_version( "2021-07-15T11:48:46+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-15 11:48:46 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "creation_date", value: "2012-10-25 10:12:52 +0200 (Thu, 25 Oct 2012)" );
	script_name( "PHP Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of PHP." );
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
paths = ssh_find_file( file_name: "/php(-cli|[578](\\.[0-9])?)?$", sock: sock, useregex: TRUE );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
for path in paths {
	path = chomp( path );
	if(!path){
		continue;
	}
	if(path == "/etc/alternatives/php"){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: path, sock: sock, version_argv: "-vn", ver_pattern: "PHP ([^ ]+)" );
	if(!vers[1] || !IsMatchRegexp( vers[1], "^[0-9.]{3,}" ) || ContainsString( vers[0], "The PHP Group" )){
		continue;
	}
	set_kb_item( name: "php/detected", value: TRUE );
	set_kb_item( name: "php/ssh-login/detected", value: TRUE );
	cpe = build_cpe( value: vers[1], exp: "([0-9.]+)", base: "cpe:/a:php:php:" );
	if(!cpe){
		cpe = "cpe:/a:php:php";
	}
	register_product( cpe: cpe, location: path, port: 0, service: "ssh-login" );
	log_message( data: build_detection_report( app: "PHP", version: vers[1], install: path, cpe: cpe, concluded: vers[0] ), port: 0 );
}
exit( 0 );

