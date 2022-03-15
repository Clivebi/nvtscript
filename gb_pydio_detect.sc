if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113003" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-09-27 12:06:59 +0200 (Wed, 27 Sep 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Pydio Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running Pydio, a file explorer
  for remotely managing files on a web server." );
	script_xref( name: "URL", value: "https://pydio.com/de" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/pydio", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php?get_action=get_boot_conf";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(buf == NULL){
		continue;
	}
	if(egrep( pattern: "\"ajxpVersion\"", string: buf )){
		version_number = NASLString( "unknown" );
		version = eregmatch( string: buf, pattern: "\"ajxpVersion\":\"([0-9.]+)\"", icase: TRUE );
		if(!isnull( version[1] )){
			version_number = chomp( version[1] );
		}
		tmp_version = version_number + " under " + install;
		set_kb_item( name: "www/" + port + "/pydio", value: tmp_version );
		set_kb_item( name: "pydio/installed", value: TRUE );
		cpe = build_cpe( value: version_number, exp: "([0-9.]+)", base: "cpe:/a:pydio:pydio:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:pydio:pydio";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Pydio", version: version_number, install: install, cpe: cpe, concludedUrl: url, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

