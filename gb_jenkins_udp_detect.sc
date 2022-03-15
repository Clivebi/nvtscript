if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142666" );
	script_version( "2021-05-25T11:10:13+0000" );
	script_tag( name: "last_modification", value: "2021-05-25 11:10:13 +0000 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2019-07-24 08:20:18 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Jenkins Detection (Auto Discovery)" );
	script_tag( name: "summary", value: "Auto Discovery service based detection of the Jenkins automation
  server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_open_udp_ports.sc" );
	script_require_udp_ports( "Services/udp/unknown", 33848 );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( default: 33848, ipproto: "udp" );
if(!soc = open_sock_udp( port )){
	exit( 0 );
}
send( socket: soc, data: "\\n" );
recv = recv( socket: soc, length: 512 );
close( soc );
if(!recv || !ContainsString( recv, "<hudson><" ) || !ContainsString( recv, "<server-id>" )){
	exit( 0 );
}
version = "unknown";
set_kb_item( name: "jenkins/detected", value: TRUE );
set_kb_item( name: "jenkins/autodiscovery/detected", value: TRUE );
set_kb_item( name: "jenkins/autodiscovery/port", value: port );
vers = eregmatch( pattern: "<version>([0-9.]+)</version>", string: recv );
if(!isnull( vers[1] )){
	version = vers[1];
	if(IsMatchRegexp( version, "^[0-9]+\\.[0-9]+\\.[0-9]+" )){
		set_kb_item( name: "jenkins/" + port + "/is_lts", value: TRUE );
	}
}
set_kb_item( name: "jenkins/autodiscovery/" + port + "/version", value: version );
set_kb_item( name: "jenkins/autodiscovery/" + port + "/concluded", value: recv );
exit( 0 );

