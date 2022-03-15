if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100324" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "TFT Gallery Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.tftgallery.org" );
	script_tag( name: "summary", value: "This host is running TFT Gallery, an easy-to-use image gallery
  using PHP." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/gallery", "/photos", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(!buf){
		continue;
	}
	if(egrep( pattern: "<meta name=\"generator\" content=\"(TFT Gallery|TFTgallery)", string: buf, icase: TRUE )){
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "(TFT Gallery|TFTgallery) ([0-9.]+)", icase: TRUE );
		if(!isnull( vers[2] )){
			version = chomp( vers[2] );
		}
		tmp_version = vers + " under " + install;
		set_kb_item( name: "www/" + port + "/tftgallery", value: tmp_version );
		set_kb_item( name: "tftgallery/detected", value: TRUE );
		register_and_report_cpe( app: "TFT Gallery", ver: version, concluded: vers[0], base: "cpe:/a:tftgallery:tftgallery:", expr: "^([0-9.]+)", insloc: install, regPort: port );
		exit( 0 );
	}
}
exit( 0 );

