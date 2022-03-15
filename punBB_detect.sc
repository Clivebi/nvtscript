if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15936" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PunBB detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.punbb.org/" );
	script_tag( name: "summary", value: "The remote web server contains a database management application
  written in PHP.

  Description :

  This script detects whether the remote host is running PunBB and
  extracts the version number and location if found.

  PunBB is an open-source discussion board written in PHP." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "PunBB detection";
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/punbb", "/forum", "/forums", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	pat = "Powered by .*http://www\\.punbb\\.org/.>PunBB";
	if(egrep( pattern: pat, string: buf )){
		version = eregmatch( pattern: NASLString( ".*", pat, "</a><br>.+Version: (.+)<br>.*" ), string: buf );
		if( version == NULL ){
			version = "unknown";
			report = NASLString( "An unknown version of PunBB is installed under ", install, " on the remote host." );
		}
		else {
			version = version[1];
			report = NASLString( "PunBB version ", version, " is installed under ", install, " on the remote host." );
		}
		log_message( port: port, data: report );
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/punBB", value: tmp_version );
		set_kb_item( name: "punBB/installed", value: TRUE );
		cpe = build_cpe( value: tmp_version, exp: "^([0-9.]+\\.[0-9])\\.?([a-z0-9]+)?", base: "cpe:/a:punbb:punbb:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
exit( 0 );

