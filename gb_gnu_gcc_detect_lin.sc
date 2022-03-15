if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806083" );
	script_version( "2021-06-14T09:56:19+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-14 09:56:19 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-10-13 11:46:09 +0530 (Tue, 13 Oct 2015)" );
	script_name( "GNU GCC Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of GNU GCC.

  The script logs in via ssh, searches for executable 'gcc' and queries the
  found executables via command line option '-v'" );
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
binary_list = ssh_find_file( file_name: "/gcc(-[0-9.]+)?$", useregex: TRUE, sock: sock );
if(!binary_list){
	ssh_close_connection();
	exit( 0 );
}
for binary_name in binary_list {
	binary_name = chomp( binary_name );
	if(!binary_name){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: binary_name, sock: sock, version_argv: "-v", ver_pattern: "gcc version ([0-9.]+).*" );
	if(vers[1]){
		set_kb_item( name: "gnu/gcc/detected", value: TRUE );
		cpe = build_cpe( value: vers[1], exp: "^([0-9.]+)", base: "cpe:/a:gnu:gcc:" );
		if(!cpe){
			cpe = "cpe:/a:gnu:gcc";
		}
		register_product( cpe: cpe, location: binary_name, port: 0, service: "ssh-login" );
		log_message( data: build_detection_report( app: "GNU GCC", version: vers[1], install: binary_name, cpe: cpe, concluded: vers[0] ), port: 0 );
	}
}
ssh_close_connection();
exit( 0 );

