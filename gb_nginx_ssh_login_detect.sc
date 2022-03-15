if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113786" );
	script_version( "2021-02-01T12:59:26+0000" );
	script_tag( name: "last_modification", value: "2021-02-01 12:59:26 +0000 (Mon, 01 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-26 11:46:55 +0100 (Tue, 26 Jan 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "nginx Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of nginx." );
	exit( 0 );
}
require("host_details.inc.sc");
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
paths = ssh_find_bin( prog_name: "nginx", sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-v", ver_pattern: "nginx version: nginx/([0-9.]+)" );
	if(isnull( vers[1] )){
		continue;
	}
	set_kb_item( name: "nginx/detected", value: TRUE );
	set_kb_item( name: "nginx/ssh-login/detected", value: TRUE );
	set_kb_item( name: "nginx/ssh-login/port", value: port );
	set_kb_item( name: "nginx/ssh-login/" + port + "/installs", value: "0#---#" + bin + "#---#" + vers[1] + "#---#" + vers[0] );
}
exit( 0 );

