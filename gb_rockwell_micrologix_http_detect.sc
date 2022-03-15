if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140662" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-01-10 10:09:48 +0700 (Wed, 10 Jan 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Rockwell Automation MicroLogix Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Rockwell Automation MicroLogix
PLC's." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ABwww/banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "A-B WWW" )){
	exit( 0 );
}
url = "/home.htm";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<title>Rockwell Automation</title>" ) && IsMatchRegexp( res, "MicroLogix [0-9]+ Processor" )){
	set_kb_item( name: "rockwell_micrologix/detected", value: TRUE );
	set_kb_item( name: "rockwell_micrologix/http/detected", value: TRUE );
	set_kb_item( name: "rockwell_micrologix/http/port", value: port );
	app = eregmatch( pattern: "MicroLogix ([0-9]+) Processor", string: res );
	device = app[1];
	app = app[0];
	version = "unknown";
	vers = eregmatch( pattern: "O(/)?S.*Revision</td><td>Series ([A-Z]) FRN ([0-9.]+)</td>", string: res );
	if(!isnull( vers[3] )){
		set_kb_item( name: "rockwell_micrologix/http/" + port + "/fw_version", value: vers[3] );
	}
	if(!isnull( vers[2] )){
		set_kb_item( name: "rockwell_micrologix/http/" + port + "/series", value: vers[2] );
	}
	dev_name = eregmatch( pattern: "Device Name</td><td>([^<]+)", string: res );
	if(!isnull( dev_name[1] )){
		set_kb_item( name: "rockwell_micrologix/http/" + port + "/model", value: dev_name[1] );
	}
	mac = eregmatch( pattern: "Ethernet Address \\(MAC\\)</td><td>([A-F0-9-]{17})", string: res );
	if(!isnull( mac[1] )){
		mac = str_replace( string: mac[1], find: "-", replace: ":" );
		set_kb_item( name: "rockwell_micrologix/http/" + port + "/mac", value: mac );
		register_host_detail( name: "MAC", value: mac, desc: "gb_rockwell_micrologix_http_detect.nasl" );
		replace_kb_item( name: "Host/mac_address", value: mac );
	}
	exit( 0 );
}
exit( 0 );

