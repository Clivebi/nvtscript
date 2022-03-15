if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113243" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Autonomic Controls Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/autonomic_controls/device/detected" );
	script_tag( name: "summary", value: "Detection for Autonomic Controls devices using Telnet." );
	script_xref( name: "URL", value: "http://www.autonomic-controls.com/products/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(IsMatchRegexp( banner, "Autonomic Controls" )){
	replace_kb_item( name: "autonomic_controls/detected", value: TRUE );
	set_kb_item( name: "autonomic_controls/telnet/port", value: port );
	ver = eregmatch( string: banner, pattern: "Autonomic Controls Remote Configuration version ([0-9.]+)", icase: TRUE );
	if(!isnull( ver[1] )){
		set_kb_item( name: "autonomic_controls/telnet/version", value: ver[1] );
		set_kb_item( name: "autonomic_controls/telnet/concluded", value: ver[0] );
	}
}
exit( 0 );

