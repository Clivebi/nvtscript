if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117229" );
	script_version( "2021-06-14T09:56:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 09:56:19 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-02-17 11:51:47 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache Tomcat Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Apache Tomcat." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
full_path_list = ssh_find_file( file_name: "/(tomcat|catalina\\.sh)$", sock: sock, useregex: TRUE );
if(!full_path_list){
	ssh_close_connection();
	exit( 0 );
}
port = kb_ssh_transport();
for full_path in full_path_list {
	full_path = chomp( full_path );
	if(!full_path){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: full_path, sock: sock, version_argv: "version", ver_pattern: "(Server version\\s*:\\s*Apache Tomcat/([0-9.-]+)|Neither the JAVA_HOME nor the JRE_HOME environment variable is defined\\s+At least one of these environment variable is needed to run this program)" );
	if(!vers || !vers[2]){
		continue;
	}
	if( ContainsString( vers[1], "Neither the JAVA_HOME nor the JRE_HOME" ) ){
		version = "unknown";
		extra = "The scanning user is misconfigured and doesn't have a 'JAVA_HOME' or 'JRE_HOME' defined (Java might be not installed). ";
		extra += "Version detection of Apache Tomcat is not possible. Please correct the setup according to the Operating System or Apache Tomcat manual.";
	}
	else {
		version = vers[2];
	}
	concluded = vers[max_index( vers ) - 1];
	set_kb_item( name: "apache/tomcat/detected", value: TRUE );
	set_kb_item( name: "apache/tomcat/ssh-login/detected", value: TRUE );
	set_kb_item( name: "apache/tomcat/ssh-login/" + port + "/installs", value: "0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---##---#" + extra );
}
ssh_close_connection();
exit( 0 );

