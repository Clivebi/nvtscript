if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117281" );
	script_version( "2021-06-14T09:56:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 09:56:19 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-30 07:49:07 +0000 (Tue, 30 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Apache Struts Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of Apache Struts." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("list_array_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
full_path_list = ssh_find_file( file_name: "/(pom\\.xml|struts2?-core-[0-9.]+\\.jar)$", sock: sock, useregex: TRUE );
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
	if( ContainsString( full_path, "/pom.xml" ) ){
		type = " (Sources)";
		buf = ssh_cmd( socket: sock, cmd: "cat " + full_path );
		if(!buf || !concl = egrep( string: buf, pattern: "^\\s+(<description>Apache Struts( 2?)</description>|Apache Struts 2 is an elegant, extensible framework|<name>Struts( 2)?</name>)", icase: FALSE )){
			continue;
		}
		version = "unknown";
		concluded = chomp( concl );
		vers = eregmatch( string: buf, pattern: "( *<version>([0-9.]{4,}[^>]*)</version>)", icase: FALSE );
		if(vers[2]){
			version = vers[2];
			concluded += "\n" + vers[1];
		}
	}
	else {
		type = " (JAR file)";
		version = "unknown";
		vers = eregmatch( string: full_path, pattern: "struts2?-core-([0-9.]+)\\.jar", icase: FALSE );
		if(vers[1]){
			version = vers[1];
			concluded = vers[0];
		}
	}
	set_kb_item( name: "apache/struts/detected", value: TRUE );
	set_kb_item( name: "apache/struts/ssh-login/detected", value: TRUE );
	set_kb_item( name: "apache/struts/ssh-login/" + port + "/installs", value: "0#---#" + full_path + "#---#" + version + "#---#" + concluded + "#---#" + type );
}
ssh_close_connection();
exit( 0 );

