if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105458" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-12T06:55:50+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 06:55:50 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-11-18 13:39:52 +0100 (Wed, 18 Nov 2015)" );
	script_name( "Cisco Network Analysis Module Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of the Cisco Network Analysis Module." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/authenticate/login";
buf = http_get_cache( port: port, item: url );
if(( ContainsString( buf, "<title>NAM Login</title>" ) && ContainsString( buf, "Cisco Prime" ) ) || ( ContainsString( buf, "productName=\"Network Analysis Module\"" ) )){
	version = "unknown";
	set_kb_item( name: "cisco/nam/detected", value: TRUE );
	set_kb_item( name: "cisco/nam/http/port", value: port );
	vers = eregmatch( pattern: "productVersion=\"Version ([^\"]+)\"", string: buf );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "cisco/nam/http/" + port + "/concluded", value: vers[0] );
	}
	set_kb_item( name: "cisco/nam/http/" + port + "/version", value: version );
}
exit( 0 );

