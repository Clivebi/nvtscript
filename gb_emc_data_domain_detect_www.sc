if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140145" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)" );
	script_name( "EMC Data Domain Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of EMC Data Domain." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/ddem/login/";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "companyName\":\"Data Domain\"" ) || !ContainsString( buf, "DD System Manager Login" )){
	exit( 0 );
}
set_kb_item( name: "emc/data_domain/installed", value: TRUE );
vb = eregmatch( pattern: ",\"appVersion\":\"([0-9.]+[^-]+)-([0-9]+)\"", string: buf );
if(!isnull( vb[1] )){
	replace_kb_item( name: "emc/data_domain/version/http", value: vb[1] );
}
if(!isnull( vb[2] )){
	replace_kb_item( name: "emc/data_domain/build/http", value: vb[2] );
}
log_message( port: port, data: "The EMC Data Domain System Manager is running at this port." );
exit( 0 );

