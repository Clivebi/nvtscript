if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10707" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "McAfee myCIO HTTP Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 6515 );
	script_mandatory_keys( "myCIO/banner" );
	script_tag( name: "solution", value: "Configure your firewall to block access to this port (TCP 6515)." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "We detected the presence of McAfee's myCIO HTTP Server.
  The server provides other clients on the network with antivirus updates.
  Several security vulnerabilities have been found in the past in the myCIO
  product.

  It is advisable that you block access to this port (TCP 6515) from untrusted
  networks." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 6515 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "myCIO" )){
	set_kb_item( name: "mycio/installed", value: TRUE );
	set_kb_item( name: "mycio/" + port + "/installed", value: TRUE );
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

