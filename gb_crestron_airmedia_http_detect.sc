if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113391" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-16 10:16:17 +0200 (Thu, 16 May 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Crestron AirMedia Presentation Gateway Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of Crestron AirMedia Presentation
  Gateway devices." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html";
buf = http_get_cache( item: url, port: port );
if( IsMatchRegexp( buf, "^HTTP/[0-9]([.][0-9]+)? 200" ) && ContainsString( buf, "<title>Crestron AirMedia</title>" ) ){
	detected = TRUE;
}
else {
	url = "/index_airmedia.html";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/[0-9]([.][0-9]+)? 200" ) && ( ContainsString( buf, "<title>Crestron AirMedia</title>" ) && ContainsString( buf, "Crestron Webserver" ) )){
		detected = TRUE;
	}
}
if(detected){
	set_kb_item( name: "crestron_airmedia/detected", value: TRUE );
	set_kb_item( name: "crestron_airmedia/http/detected", value: TRUE );
	set_kb_item( name: "crestron_airmedia/http/port", value: port );
	set_kb_item( name: "crestron_airmedia/http/" + port + "/concludedUrl", value: url );
}
exit( 0 );

