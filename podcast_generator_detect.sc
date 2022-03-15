if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100134" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-16 19:20:22 +0200 (Thu, 16 Apr 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Podcast Generator Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://podcastgen.sourceforge.net/" );
	script_tag( name: "summary", value: "This host is running Podcast Generator, a free web based podcast
  publishing script written in PHP." );
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
for dir in nasl_make_list_unique( "/podcast", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(isnull( buf )){
		continue;
	}
	if(egrep( pattern: "Powered by <a [^>]+>Podcast Generator</a>", string: buf, icase: TRUE )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "<meta name=\"Generator\" content=\"Podcast Generator ([0-9.]+[a-z ]*[0-9]*)\"", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		tmp_version = vers + " under " + install;
		set_kb_item( name: "www/" + port + "/podcast_generator", value: tmp_version );
		set_kb_item( name: "podcast_generator/detected", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+)([a-z 0-9]+)?", base: "cpe:/a:podcast_generator:podcast_generator:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:podcast_generator:podcast_generator";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Podcast Generator", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

