if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901036" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-29 07:53:15 +0100 (Thu, 29 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SystemTap Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of SystemTap." );
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
paths = ssh_find_bin( prog_name: "stap", sock: sock );
for systemtapbin in paths {
	systemtapbin = chomp( systemtapbin );
	if(!systemtapbin){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: systemtapbin, sock: sock, version_argv: "-V", ver_pattern: "version ([0-9.]+)" );
	if(!isnull( vers[1] ) && ContainsString( vers, "SystemTap" )){
		set_kb_item( name: "SystemTap/Ver", value: vers[1] );
		cpe = build_cpe( value: vers[1], exp: "^([0-9.]+)", base: "cpe:/a:systemtap:systemtap:" );
		if(!cpe){
			cpe = "cpe:/a:systemtap:systemtap";
		}
		register_product( cpe: cpe, location: systemtapbin, port: 0, service: "ssh-login" );
		log_message( data: build_detection_report( app: "SystemTap", version: vers[1], install: systemtapbin, cpe: cpe, concluded: vers[0] ), port: 0 );
	}
}
ssh_close_connection();

