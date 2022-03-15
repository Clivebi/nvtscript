if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150506" );
	script_version( "2021-06-15T12:51:17+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:51:17 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-12-30 11:55:56 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read /etc/inetd.* and /etc/xinetd.* files" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://linux.die.net/man/8/xinetd" );
	script_tag( name: "summary", value: "xinetd performs the same function as inetd: it starts programs
that provide Internet services. Instead of having such servers started at system initialization time,
and be dormant until a connection request arrives, xinetd is the only daemon process started and it
listens on all service ports for the services listed in its configuration file. When a request comes
in, xinetd starts the appropriate server. Because of the way it operates, xinetd (as well as inetd)
is also referred to as a super-server.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
func parse_xinetd_conf( filepath, socket ){
	var filepath, socket, cmd, ret, services, service, service_name, pattern, settings;
	cmd = "cat " + filepath + " 2>/dev/null";
	ret = ssh_cmd( socket: socket, cmd: cmd );
	if(!ret){
		return;
	}
	services = egrep( string: ret, pattern: "^\\s*service", multiline: TRUE );
	for service in split( buffer: services, keep: FALSE ) {
		service_name = eregmatch( string: chomp( service ), pattern: "^\\s*service\\s+(.+)" );
		pattern = service + "\\s+\\{([^}]+)\\}";
		settings = eregmatch( string: ret, pattern: pattern );
		if(service_name && settings){
			set_kb_item( name: "Policy/linux/etc/xinetd.conf/" + service_name[1], value: settings[1] );
		}
	}
	return;
}
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/inetd/ssh/ERROR", value: TRUE );
	set_kb_item( name: "Policy/linux/xinetd/ssh/ERROR", value: TRUE );
	exit( 0 );
}
inetd_files = "/etc/inetd.*";
filelist = ssh_find_file( file_name: inetd_files, sock: sock, useregex: TRUE );
if( !filelist ){
	set_kb_item( name: "Policy/linux/inetd/ERROR", value: TRUE );
}
else {
	for file in filelist {
		policy_linux_file_content( socket: sock, file: chomp( file ) );
	}
}
xinetd_files = "/etc/xinetd.*";
filelist = ssh_find_file( file_name: xinetd_files, sock: sock, useregex: TRUE );
if( !filelist ){
	set_kb_item( name: "Policy/linux/xinetd/ERROR", value: TRUE );
}
else {
	for file in filelist {
		if( IsMatchRegexp( file, "xinetd\\.conf" ) ) {
			parse_xinetd_conf( filepath: file, socket: sock );
		}
		else {
			policy_linux_file_content( socket: sock, file: chomp( file ) );
		}
	}
}
exit( 0 );

