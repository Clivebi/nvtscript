if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108546" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-02-09 16:58:00 +0100 (Sat, 09 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OSSEC/Wazuh ossec-authd Service Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "find_service6.sc" );
	script_require_ports( "Services/unknown", 1515 );
	script_xref( name: "URL", value: "https://www.ossec.net/" );
	script_tag( name: "summary", value: "This script tries to detect an installed OSSEC/Wazuh ossec-authd service
  on the remote host." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = unknownservice_get_port( default: 1515 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
req = "OSSEC A:'" + this_host_name() + "'" + "\n";
send( socket: soc, data: req );
buf = recv_line( socket: soc, length: 512 );
close( soc );
if(!buf || ( !IsMatchRegexp( buf, "^OSSEC K:'.+'" ) && !ContainsString( buf, "ERROR: Unable to add agent." ) )){
	exit( 0 );
}
service_register( port: port, proto: "ossec-authd" );
set_kb_item( name: "ossec_wazuh/authd/detected", value: TRUE );
set_kb_item( name: "ossec_wazuh/authd/no_auth", value: TRUE );
set_kb_item( name: "ossec_wazuh/authd/" + port + "/detected", value: TRUE );
set_kb_item( name: "ossec_wazuh/authd/" + port + "/no_auth", value: TRUE );
log_message( port: port, data: "An ossec-authd service seems to be running on this port." );
exit( 0 );

