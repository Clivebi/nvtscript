if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143418" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-29 06:59:00 +0000 (Wed, 29 Jan 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LANCOM Device Detection (SSH)" );
	script_tag( name: "summary", value: "Detection of LANCOM devices.

  This script performs SSH based detection of LANCOM devices." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/lancom/detected" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner){
	exit( 0 );
}
if(egrep( pattern: "SSH.+-lancom", string: banner )){
	version = "unknown";
	model = "unknown";
	set_kb_item( name: "lancom/detected", value: TRUE );
	set_kb_item( name: "lancom/ssh/detected", value: TRUE );
	set_kb_item( name: "lancom/ssh/port", value: port );
	set_kb_item( name: "lancom/ssh/" + port + "/detected", value: TRUE );
	set_kb_item( name: "lancom/ssh/" + port + "/version", value: version );
	set_kb_item( name: "lancom/ssh/" + port + "/model", value: version );
	set_kb_item( name: "lancom/ssh/" + port + "/concluded", value: banner );
}
exit( 0 );

