if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17296" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 158 );
	script_cve_id( "CVE-1999-1196" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Kill service with random data" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Denial of Service" );
	script_mandatory_keys( "TCP/PORTS" );
	script_dependencies( "find_service.sc", "find_service2.sc", "secpod_open_tcp_ports.sc" );
	script_tag( name: "solution", value: "Upgrade your software or contact your vendor and inform it of this
  vulnerability." );
	script_tag( name: "summary", value: "It was possible to crash the remote service by sending it
  a few kilobytes of random data." );
	script_tag( name: "impact", value: "An attacker may use this flaw to make this service crash continuously,
  preventing this service from working properly. It may also be possible
  to exploit this flaw to execute arbitrary code on this host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
beurk = "";
for(i = 0;i < 256;i++){
	beurk = strcat( beurk, ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ), ord( rand() % 256 ) );
}
port = tcp_get_all_port();
soc = open_sock_tcp( port );
if(soc){
	send( socket: soc, data: beurk );
	close( soc );
	for(i = 1;i <= 3;i++){
		soc = open_sock_tcp( port );
		if(soc){
			break;
		}
		sleep( i );
	}
	if( !soc ){
		security_message( port: port );
	}
	else {
		close( soc );
	}
}
exit( 0 );

