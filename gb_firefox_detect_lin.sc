if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800017" );
	script_version( "2021-06-23T05:58:47+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-23 05:58:47 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "creation_date", value: "2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)" );
	script_name( "Mozilla Firefox Detection (Linux/Unix SSH Login)" );
	script_tag( name: "summary", value: "SSH login-based detection of Mozilla Firefox." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
files = ssh_find_file( file_name: "/firefox$", useregex: TRUE, sock: sock );
for file in files {
	binary_name = chomp( file );
	if(!binary_name){
		continue;
	}
	version = ssh_get_bin_version( full_prog_name: binary_name, sock: sock, version_argv: "-v", ver_pattern: "Mozilla Firefox ([0-9.]+([a-z0-9]+)?)" );
	if(!isnull( version[1] )){
		set_kb_item( name: "Firefox/Linux/Ver", value: version[1] );
		set_kb_item( name: "Firefox/Linux_or_Win/installed", value: TRUE );
		set_kb_item( name: "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Linux/Installed", value: TRUE );
		set_kb_item( name: "mozilla/firefox/linux/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/linux_macosx/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/linux_windows/detected", value: TRUE );
		set_kb_item( name: "mozilla/firefox/windows_linux_macosx/detected", value: TRUE );
		cpe = build_cpe( value: version[1], exp: "^([0-9.a-z]+)", base: "cpe:/a:mozilla:firefox:" );
		if(!cpe){
			cpe = "cpe:/a:mozilla:firefox";
		}
		register_product( cpe: cpe, location: file, port: 0, service: "ssh-login" );
		log_message( data: build_detection_report( app: "Firefox", version: version[1], install: file, cpe: cpe, concluded: version[0] ) );
	}
}
ssh_close_connection();
exit( 0 );

