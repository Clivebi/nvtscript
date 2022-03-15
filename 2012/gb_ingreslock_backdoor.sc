if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103549" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-08-22 16:21:38 +0200 (Wed, 22 Aug 2012)" );
	script_name( "Possible Backdoor: Ingreslock" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service1.sc", "find_service2.sc", "secpod_open_tcp_ports.sc" );
	script_mandatory_keys( "TCP/PORTS" );
	script_tag( name: "summary", value: "A backdoor is installed on the remote host." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary commands in the
  context of the application. Successful attacks will compromise the affected isystem." );
	script_tag( name: "solution", value: "A whole cleanup of the infected system is recommended." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = tcp_get_all_port();
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
recv = recv( socket: soc, length: 1024 );
send( socket: soc, data: "id;\r\n\r\n" );
recv = recv( socket: soc, length: 1024 );
close( soc );
if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+" )){
	uid = eregmatch( pattern: "(uid=[0-9]+.*gid=[0-9]+[^ ]+)", string: recv );
	if(uid){
		report = "The service is answering to an 'id;' command with the following response: " + uid[1];
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

