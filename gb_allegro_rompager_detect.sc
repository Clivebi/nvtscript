if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105153" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_name( "Allegro RomPager Detection (HTTP)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2014-12-23 10:00:24 +0100 (Tue, 23 Dec 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Allegro/banner" );
	script_tag( name: "summary", value: "HTTP based detection of Allegro RomPager." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
CPE = "cpe:/a:allegrosoft:rompager:";
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/Allegro";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(concl = egrep( string: buf, pattern: "(RomPager Advanced Version|^Server\\s*:\\s*(Allegro-Software-)?RomPager)", icase: TRUE )){
	concl = chomp( concl );
	set_kb_item( name: "allegro/rompager/detected", value: TRUE );
	version = "unknown";
	vers = eregmatch( string: buf, pattern: "RomPager/([0-9][0-9a-z.]+)" );
	if(isnull( vers[1] )){
		vers = eregmatch( string: buf, pattern: "RomPager Advanced Version ([0-9.]+)" );
	}
	if(!isnull( version[1] )){
		version = chomp( vers[1] );
	}
	register_and_report_cpe( app: "Allegro RomPager", ver: version, concluded: concl, base: CPE, expr: "([0-9.]+)([0-9a-z.-]+)?", insloc: port + "/tcp", regPort: port, regService: "www" );
}
exit( 0 );

