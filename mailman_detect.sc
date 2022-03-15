if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16338" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Mailman Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 George A. Theall" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.list.org/" );
	script_tag( name: "summary", value: "This script detects whether the remote host is running Mailman and
  extracts version numbers and locations of any instances found.

  Mailman is a Python-based mailing list management package from the GNU Project." );
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
for dir in nasl_make_list_unique( "/mailman", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( "/listinfo",
		 "/listinfo.cgi",
		 "/listinfo.py" ) {
		url = dir + url;
		res = http_get_cache( item: url, port: port );
		if(IsMatchRegexp( res, "alt=.Delivered by Mailman" )){
			version = "unknown";
			vers = eregmatch( pattern: "alt=.Delivered by Mailman.[^\r\n]+>version ([^<]+)", string: res );
			if(!isnull( vers[1] )){
				version = chomp( vers[1] );
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			set_kb_item( name: "gnu_mailman/detected", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:gnu:mailman:" );
			if(!cpe){
				cpe = "cpe:/a:gnu:mailman";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Mailman", version: version, install: install, cpe: cpe, concludedUrl: concUrl, concluded: vers[0] ), port: port );
			break;
		}
	}
}
exit( 0 );

