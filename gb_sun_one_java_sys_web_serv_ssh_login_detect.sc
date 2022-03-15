if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108502" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-12-08 13:32:46 +0100 (Sat, 08 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Sun Java System/ONE Web Server Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH login-based detection of the Sun Java System/ONE Web Server." );
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
full_path_list = ssh_find_file( file_name: "/webservd$", useregex: TRUE, sock: sock );
for full_path in full_path_list {
	file = chomp( file );
	if(!file){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: file, sock: sock, version_argv: "-v", ver_pattern: "Sun (ONE|Java System) Web Server ([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)" );
	if(!isnull( vers[2] )){
		if( !isnull( vers[4] ) ) {
			version = vers[2] + "." + vers[4];
		}
		else {
			version = vers[2];
		}
		if( vers[1] == "ONE" ){
			set_kb_item( name: "sun/one_web_server/detected", value: TRUE );
			set_kb_item( name: "sun/one_web_server/ssh-login/detected", value: TRUE );
			cpe_base = "cpe:/a:sun:one_web_server:";
			app_name = "Sun ONE Web Server";
		}
		else {
			set_kb_item( name: "sun/java_system_web_server/detected", value: TRUE );
			set_kb_item( name: "sun/java_system_web_server/ssh-login/detected", value: TRUE );
			cpe_base = "cpe:/a:sun:java_system_web_server:";
			app_name = "Sun Java System Web Server";
		}
		set_kb_item( name: "oracle_or_sun/web_server/detected", value: TRUE );
		set_kb_item( name: "oracle_or_sun/web_server/ssh-login/detected", value: TRUE );
		register_and_report_cpe( app: app_name, ver: version, base: cpe_base, expr: "([0-9.]+)", regPort: 0, insloc: file, concluded: vers[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

