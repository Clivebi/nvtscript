if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108578" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-05-16 12:08:23 +0000 (Thu, 16 May 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OpenSSH Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of OpenSSH." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
known_exclusions = make_list( "/etc/ssh",
	 "/usr/lib/apt/methods/ssh",
	 "/etc/init.d/ssh",
	 "/etc/default/ssh",
	 "/etc/pam.d/sshd" );
known_locations = make_list( "/usr/bin/ssh",
	 "/usr/local/bin/ssh",
	 "/usr/sbin/sshd",
	 "/usr/local/sbin/sshd" );
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
port = kb_ssh_transport();
path_list = ssh_find_file( file_name: "/sshd?$", sock: sock, useregex: TRUE );
if(!path_list || !is_array( path_list )){
	ssh_close_connection();
	exit( 0 );
}
for known_location in known_locations {
	if(!in_array( search: known_location, array: path_list, part_match: FALSE )){
		path_list = make_list( path_list,
			 known_location );
	}
}
for path in path_list {
	path = chomp( path );
	if(!path){
		continue;
	}
	if(in_array( search: path, array: known_exclusions, part_match: FALSE )){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: path, sock: sock, version_argv: "-V", ver_pattern: "OpenSSH_([.a-zA-Z0-9]+)[- ]?[^\r\n]+" );
	if(vers[1]){
		version = vers[1];
		found = TRUE;
		if( ContainsString( vers[max_index( vers ) - 1], "usage: sshd" ) ) {
			type = "Server";
		}
		else {
			type = "Client";
		}
		set_kb_item( name: "openssh/ssh-login/" + port + "/installs", value: "0#---#" + path + "#---#" + version + "#---#" + vers[0] + "#---#" + type );
	}
}
if(found){
	set_kb_item( name: "openssh/detected", value: TRUE );
	set_kb_item( name: "openssh/ssh-login/detected", value: TRUE );
	set_kb_item( name: "openssh/ssh-login/port", value: port );
}
exit( 0 );

