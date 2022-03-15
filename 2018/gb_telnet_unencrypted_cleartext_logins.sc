if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108522" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-20 07:47:54 +0100 (Thu, 20 Dec 2018)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "Telnet Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "impact", value: "An attacker can uncover login names and passwords by sniffing traffic to the
  Telnet service." );
	script_tag( name: "solution", value: "Replace Telnet with a protocol like SSH which supports encrypted connections." );
	script_tag( name: "summary", value: "The remote host is running a Telnet service that allows cleartext logins over
  unencrypted connections." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 99 );
}
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(!telnet_has_login_prompt( data: banner )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "(For security reasons, a TLS/SSL enabled telnet client MUST be used to connect|Encryption is required\\. Access is denied\\.)" )){
	exit( 99 );
}
security_message( port: port );
exit( 0 );

