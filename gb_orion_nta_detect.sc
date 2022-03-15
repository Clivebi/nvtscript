if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105959" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-03-06 15:12:25 +0700 (Fri, 06 Mar 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "SolarWinds Orion Netflow Traffic Analyzer Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8787 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks for the presence of SolarWinds Orion Netflow Traffic Analyzer." );
	script_xref( name: "URL", value: "http://www.solarwinds.com/products/orion/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8787 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
dir = "/Orion";
url = NASLString( dir, "/Login.aspx" );
buf = http_get_cache( item: url, port: port );
if(!buf){
	exit( 0 );
}
if(ContainsString( buf, "SolarWinds Platform" ) || ContainsString( buf, "SolarWinds Orion" ) || ContainsString( buf, "Orion Platform" )){
	nta = eregmatch( string: buf, pattern: "NTA ([0-9.]+)", icase: TRUE );
	if(!isnull( nta )){
		vers = NASLString( "unknown" );
		if(!isnull( nta[1] )){
			vers = chomp( nta[1] );
		}
		set_kb_item( name: NASLString( "www/", port, "/orion_nta" ), value: vers );
		set_kb_item( name: "orion_nta/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:solarwinds:netflow_traffic_analyzer:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:solarwinds:netflow_traffic_analyzer";
		}
		register_product( cpe: cpe, location: dir, port: port, service: "www" );
		log_message( data: build_detection_report( app: "SolarWinds Netflow Traffic Analyzer", version: vers, install: dir, cpe: cpe, concluded: nta[0] ), port: port );
	}
}
exit( 0 );

