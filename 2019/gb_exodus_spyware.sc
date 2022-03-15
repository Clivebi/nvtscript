if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108563" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-03-31 12:08:27 +0000 (Sun, 31 Mar 2019)" );
	script_name( "Exodus Android Spyware Detection" );
	script_category( ACT_ATTACK );
	script_family( "Malware" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 6200, 6842 );
	script_tag( name: "summary", value: "The remote Android device seems to be infected by the Exodus spyware." );
	script_tag( name: "vuldetect", value: "- opens a connection to port 6200/tcp and/or 6842/tcp

  - sends an additional 'sh' command on port 6200/tcp

  - checks the response if the remote device is infected and provides a remote shell" );
	script_tag( name: "solution", value: "A whole cleanup of the infected system is recommended." );
	script_xref( name: "URL", value: "https://www.securitywithoutborders.org/blog/2019/03/29/exodus.html" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("socket_func.inc.sc");
cmds = exploit_commands( "linux" );
for port in make_list( 6200,
	 6842 ) {
	if(!get_port_state( port )){
		continue;
	}
	if(!soc = open_sock_tcp( port )){
		continue;
	}
	if( port == 6200 ){
		res = socket_send_recv( soc: soc, data: "sh\n", length: 64 );
	}
	else {
		res = socket_send_recv( soc: soc, length: 64 );
	}
	if(!res || !IsMatchRegexp( res, ":[/~].*[\\$#]" )){
		close( soc );
		continue;
	}
	for pattern in keys( cmds ) {
		cmd = cmds[pattern];
		res = socket_send_recv( soc: soc, data: cmd + "\n", length: 64 );
		if(!res){
			continue;
		}
		if(egrep( pattern: pattern, string: res )){
			close( soc );
			security_message( port: port, data: "The Exodus Android Spyware seems to be running at this port.\n\nResponse:\n\n" + res );
			exit( 0 );
		}
	}
	close( soc );
}
exit( 0 );

