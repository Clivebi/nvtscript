if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17583" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-05-05T09:44:01+0000" );
	script_tag( name: "last_modification", value: "2020-05-05 09:44:01 +0000 (Tue, 05 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Aventail ASAP detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Service detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 8443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Filter incoming traffic to this port." );
	script_tag( name: "summary", value: "The remote host seems to be an Aventail SSL VPN appliance,
  connections are allowed to the web console management.

  Letting attackers know that you are using this software will help
  them to focus their attack or will make them change their strategy.

  In addition to this, an attacker may attempt to set up a brute force attack
  to log into the remote interface." );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 8443;
if(!get_port_state( port )){
	exit( 0 );
}
url = "/console/login.do";
req = http_get( item: url, port: port );
rep = http_send_recv( data: req, port: port );
if(!rep){
	exit( 0 );
}
if(ContainsString( rep, "<title>ASAP Management Console Login</title>" )){
	report = http_report_vuln_url( port: port, url: url );
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

