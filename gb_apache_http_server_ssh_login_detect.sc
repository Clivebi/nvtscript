if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117233" );
	script_version( "2021-06-14T09:56:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 09:56:19 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 11:11:24 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache HTTP Server Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of the Apache HTTP Server." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("list_array_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
full_path_list = make_list( "/usr/sbin/apache2",
	 "/usr/sbin/apache",
	 "/usr/sbin/httpd" );
found_path_list = ssh_find_file( file_name: "/(httpd|apache2?)$", sock: sock, useregex: TRUE );
if(found_path_list){
	for found_path in found_path_list {
		found_path = chomp( found_path );
		if(!found_path){
			continue;
		}
		full_path_list = nasl_make_list_unique( full_path_list, found_path );
	}
}
port = kb_ssh_transport();
for full_path in full_path_list {
	vers = ssh_get_bin_version( full_prog_name: full_path, sock: sock, version_argv: "-v", ver_pattern: "Server version\\s*:\\s*Apache/([0-9.]+(-(alpha|beta))?)" );
	if(!vers || !vers[1]){
		continue;
	}
	version = vers[1];
	concluded = vers[max_index( vers ) - 1];
	set_kb_item( name: "apache/http_server/detected", value: TRUE );
	set_kb_item( name: "apache/http_server/ssh-login/detected", value: TRUE );
	set_kb_item( name: "apache/http_server/ssh-login/" + port + "/installs", value: "0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---##---#" );
}
ssh_close_connection();
exit( 0 );

