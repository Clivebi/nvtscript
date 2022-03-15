if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103111" );
	script_version( "2020-12-23T12:52:58+0000" );
	script_tag( name: "last_modification", value: "2020-12-23 12:52:58 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2011-03-08 14:02:18 +0100 (Tue, 08 Mar 2011)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Interleave Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.interleave.nl" );
	script_tag( name: "summary", value: "HTTP based detection of Interleave." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/interleave", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<title>Interleave Business Process Management", string: buf, icase: TRUE ) && ContainsString( buf, "Please enter your username and password" )){
		set_kb_item( name: "interleave/detected", value: TRUE );
		vers = "unknown";
		url = dir + "/README";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		version = eregmatch( string: buf, pattern: "Current version is ([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		register_and_report_cpe( app: "Interleave", ver: vers, concluded: version[0], base: "cpe:/a:atomos:interleave:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: url );
		exit( 0 );
	}
}
exit( 0 );

