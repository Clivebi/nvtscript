if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108939" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-10-08 09:07:41 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "dmidecode Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.nongnu.org/dmidecode/" );
	script_tag( name: "summary", value: "SSH login-based detection of dmidecode." );
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
full_path_list = ssh_find_file( file_name: "/dmidecode$", sock: sock, useregex: TRUE );
if(!full_path_list){
	ssh_close_connection();
	exit( 0 );
}
for full_path in full_path_list {
	full_path = chomp( full_path );
	if(!full_path){
		continue;
	}
	res = ssh_cmd( socket: sock, cmd: full_path, return_errors: TRUE, return_linux_errors_only: TRUE );
	res = chomp( res );
	if(!res){
		continue;
	}
	vers = eregmatch( string: res, pattern: "^# dmidecode ([0-9]+\\.[0-9.]+)", icase: FALSE );
	if(vers[1]){
		version = vers[1];
		if( ContainsString( res, "/dev/mem: Permission denied" ) || IsMatchRegexp( res, "/sys/firmware/dmi/tables.+: Permission denied" ) ) {
			set_kb_item( name: "dmidecode/ssh-login/no_permissions", value: TRUE );
		}
		else {
			set_kb_item( name: "dmidecode/ssh-login/full_permissions", value: TRUE );
		}
		set_kb_item( name: "dmidecode/detected", value: TRUE );
		set_kb_item( name: "dmidecode/ssh-login/detected", value: TRUE );
		register_and_report_cpe( app: "dmidecode", ver: version, base: "cpe:/a:nongnu:dmidecode:", expr: "([0-9.]+)", regPort: 0, insloc: full_path, concluded: vers[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

