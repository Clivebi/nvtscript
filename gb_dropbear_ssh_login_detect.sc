if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112868" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-26 09:37:11 +0000 (Fri, 26 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Dropbear Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Dropbear." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
paths = ssh_find_file( file_name: "/dbclient$", sock: sock, useregex: TRUE );
found = FALSE;
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-V", ver_pattern: "Dropbear (client )?v([0-9.]+)" );
	if(!isnull( ver[2] )){
		version = ver[2];
		found = TRUE;
		set_kb_item( name: "dropbear_ssh/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + version + "#---#" + ver[0] );
	}
}
if(found){
	set_kb_item( name: "dropbear_ssh/detected", value: TRUE );
	set_kb_item( name: "dropbear_ssh/ssh-login/detected", value: TRUE );
	set_kb_item( name: "dropbear_ssh/ssh-login/port", value: port );
}
ssh_close_connection();
exit( 0 );

