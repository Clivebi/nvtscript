if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800019" );
	script_version( "2021-07-19T10:51:38+0000" );
	script_tag( name: "last_modification", value: "2021-07-19 10:51:38 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "creation_date", value: "2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Mozilla SeaMonkey Detection (Linux/Unix SSH Login)" );
	script_family( "Product detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Mozilla SeaMonkey." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/(seamonkey|iceape)$", useregex: TRUE, sock: sock );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
for bin in paths {
	vers = ssh_get_bin_version( full_prog_name: bin, version_argv: "-v", ver_pattern: "^Mozilla\\sSeaMonkey\\s([0-9]+\\.[0-9.]+(\\s(RC\\s[0-9]+|Alpha|Beta))?)$" );
	if(vers[1]){
		set_kb_item( name: "Seamonkey/Linux/Ver", value: vers[1] );
		set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value: TRUE );
		cpeVer = str_replace( string: vers[1], find: " ", replace: "." );
		cpe = "cpe:/a:mozilla:seamonkey:" + cpeVer;
		register_product( cpe: cpe, location: bin, port: 0, service: "ssh-login" );
		log_message( data: build_detection_report( app: "Mozilla SeaMonkey", version: vers[1], install: bin, cpe: cpe, concluded: vers[0] ), port: 0 );
	}
}
ssh_close_connection();
exit( 0 );

