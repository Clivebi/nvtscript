if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113560" );
	script_version( "2021-07-14T14:34:23+0000" );
	script_tag( name: "last_modification", value: "2021-07-14 14:34:23 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2019-11-11 11:11:11 +0200 (Mon, 11 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Python Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Python." );
	exit( 0 );
}
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
paths = ssh_find_file( file_name: "/python[23]?$", sock: sock, useregex: TRUE );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
found = FALSE;
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "Python ([0-9.]+)" );
	if(ver[1]){
		version = ver[1];
		found = TRUE;
		set_kb_item( name: "python/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + version + "#---#" + ver[0] );
	}
}
if(found){
	set_kb_item( name: "python/detected", value: TRUE );
	set_kb_item( name: "python/ssh-login/detected", value: TRUE );
	set_kb_item( name: "python/ssh-login/port", value: port );
}
ssh_close_connection();
exit( 0 );

