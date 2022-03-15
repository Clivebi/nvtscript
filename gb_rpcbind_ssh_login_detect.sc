if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117279" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-29 10:21:42 +0000 (Mon, 29 Mar 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "rpcbind Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://sourceforge.net/projects/rpcbind/" );
	script_tag( name: "summary", value: "SSH login-based detection of rpcbind." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
full_path_list = make_list( "/sbin/rpcbind",
	 "/usr/sbin/rpcbind",
	 "/usr/local/sbin/rpcbind" );
found_path_list = ssh_find_file( file_name: "/rpcbind$", sock: sock, useregex: TRUE );
if(found_path_list){
	for found_path in found_path_list {
		found_path = chomp( found_path );
		if(!found_path){
			continue;
		}
		full_path_list = nasl_make_list_unique( full_path_list, found_path );
	}
}
for full_path in full_path_list {
	full_path = chomp( full_path );
	if(!full_path){
		continue;
	}
	buf = ssh_cmd( socket: sock, cmd: full_path + " -test" );
	if(!buf || !ContainsString( buf, "rpcbind: invalid option " ) || !ContainsString( buf, "usage: rpcbind " )){
		continue;
	}
	version = "unknown";
	concluded = "";
	extra = "";
	set_kb_item( name: "rpcbind/detected", value: TRUE );
	set_kb_item( name: "rpcbind/ssh-login/detected", value: TRUE );
	cmd = "strings " + full_path;
	buf = ssh_cmd( socket: sock, cmd: cmd, return_errors: TRUE, return_linux_errors_only: TRUE );
	if(buf && concl = egrep( string: buf, pattern: "^rpcbind-[0-9.]{3,}", icase: FALSE )){
		concl = chomp( concl );
		concluded = concl + "\n" + "via '" + cmd + "' command.";
		vers = eregmatch( string: concl, pattern: "^rpcbind-([0-9.]+)", icase: FALSE );
		if(vers[1]){
			version = vers[1];
		}
	}
	if(version == "unknown"){
		extra = "rpcbind version extraction only possible via 'strings' command. If the command isn't available on the target system please install it.";
	}
	register_and_report_cpe( app: "rpcbind", ver: version, base: "cpe:/a:rpcbind_project:rpcbind:", expr: "([0-9.]+)", regPort: 0, insloc: full_path, concluded: concluded, regService: "ssh-login", extra: extra );
}
ssh_close_connection();
exit( 0 );

