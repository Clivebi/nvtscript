if(description){
	script_tag( name: "cvss_base", value: "0.0" );
	script_oid( "1.3.6.1.4.1.25623.1.0.103514" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-07-12 16:08:56 +0200 (Thu, 12 Jul 2012)" );
	script_name( "Cobbler Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Cobbler

The script sends a connection request to the server and attempts to
extract the version number from the reply." );
	exit( 0 );
}
SCRIPT_DESC = "Cobbler Detection";
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/cobbler_api";
host = http_host_name( port: port );
xml = "<?xml version=\"1.0\"?>
<methodCall>
  <methodName>extended_version</methodName>
</methodCall>";
len = strlen( xml );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Length:", len, "\\r\\n", "\\r\\n", xml );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( result, "<methodResponse>" ) || !ContainsString( result, "<name>version</name>" )){
	exit( 0 );
}
lines = split( result );
for(i = 0;i < max_index( lines );i++){
	if(ContainsString( lines[i], "<name>version</name>" )){
		version = eregmatch( pattern: "<string>([^<]+)</string>", string: lines[i + 1] );
		if(isnull( version[1] )){
			exit( 0 );
		}
		vers = version[1];
		set_kb_item( name: "Cobbler/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:michael_dehaan:cobbler:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:michael_dehaan:cobbler";
		}
		register_product( cpe: cpe, location: url, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Cobbler", version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

