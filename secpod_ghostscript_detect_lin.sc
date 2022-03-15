if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900541" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Ghostscript Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Ghostscript." );
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
binaries = ssh_find_file( file_name: "/gs$", useregex: TRUE, sock: sock );
for binary in binaries {
	binary = chomp( binary );
	if(!binary){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: binary, version_argv: "--help", ver_pattern: "Ghostscript ([0-9]\\.[0-9.]+)", sock: sock );
	if(!isnull( vers[1] )){
		res = vers[max_index( vers ) - 1];
		if(ContainsString( res, "Ghostscript" ) && ContainsString( res, "Artifex Software," )){
			set_kb_item( name: "artifex/ghostscript/lin/detected", value: TRUE );
			cpe = build_cpe( value: vers[1], exp: "^([0-9.]+)", base: "cpe:/a:artifex:ghostscript:" );
			if(!cpe){
				cpe = "cpe:/a:artifex:ghostscript";
			}
			register_product( cpe: cpe, location: binary, port: 0, service: "ssh-login" );
			report = build_detection_report( app: "Ghostscript", version: vers[1], install: binary, cpe: cpe, concluded: vers[max_index( vers ) - 1] );
			log_message( port: 0, data: report );
		}
	}
}
ssh_close_connection();
exit( 0 );

