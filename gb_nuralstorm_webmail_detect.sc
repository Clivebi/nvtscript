if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100742" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-04 13:50:35 +0200 (Wed, 04 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Nuralstorm Webmail Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.nuralstorm.net/" );
	script_tag( name: "summary", value: "This host is running Nuralstorm Webmail." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/wmail", "/webmail", "/mail", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.php";
	buf = http_get_cache( item: url, port: port );
	if(isnull( buf )){
		continue;
	}
	if(egrep( pattern: "NuralStorm Webmail - Login", string: buf, icase: TRUE )){
		vers = "unknown";
		set_kb_item( name: "nuralstorm_webmail/detected", value: TRUE );
		cpe = "cpe:/a:nuralstorm:nuralstorm_webmail";
		conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		version = eregmatch( string: buf, pattern: "Webmail \\(([^\\)]+)\\)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = str_replace( string: version[1], find: " ", replace: "" );
			vers = chomp( vers );
			cpe += ":" + vers;
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "NuralStorm Webmail", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: conclUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

