if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140687" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-15 15:48:28 +0700 (Mon, 15 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "CommuniGate Pro Detection (IMAP)" );
	script_tag( name: "summary", value: "Detection of CommuniGate Pro.

  This script performs IMAP based detection of CommuniGate Pro." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "imap4_banner.sc" );
	script_require_ports( "Services/imap", 143 );
	script_mandatory_keys( "imap/communigate/pro/detected" );
	script_xref( name: "URL", value: "https://www.communigate.com/" );
	exit( 0 );
}
require("imap_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = imap_get_port( default: 143 );
banner = imap_get_banner( port: port );
if(!ContainsString( banner, "CommuniGate Pro IMAP Server" )){
	exit( 0 );
}
set_kb_item( name: "communigatepro/detected", value: TRUE );
set_kb_item( name: "communigatepro/imap/detected", value: TRUE );
set_kb_item( name: "communigatepro/imap/port", value: port );
vers = eregmatch( pattern: "CommuniGate Pro IMAP Server ([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "communigatepro/imap/" + port + "/version", value: version );
	set_kb_item( name: "communigatepro/imap/" + port + "/concluded", value: vers[0] );
}
exit( 0 );

