if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103018" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-07 13:52:38 +0100 (Fri, 07 Jan 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "OpenEMR Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.open-emr.org/" );
	script_tag( name: "summary", value: "This host is running OpenEMR, a free medical practice management,
  electronic medical records, prescription writing, and medical billing application." );
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
for dir in nasl_make_list_unique( "/", "/openemr", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/interface/login/login.php";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "OpenEMR" )){
		set_kb_item( name: "openemr/installed", value: TRUE );
		version = "unknown";
		ver = eregmatch( pattern: "<div class=\"version\">[\r\n ]*v([0-9dev (.-]+)", string: buf );
		if(isnull( ver[1] )){
			url = dir + "/admin.php";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req );
			ver = eregmatch( pattern: "<td>([0-9dev (.-]+)\\)?</td>.*Log In</a></td>", string: buf );
		}
		if(isnull( ver[1] )){
			url = dir + "/interface/login/login_title.php";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			ver = eregmatch( string: buf, pattern: "OpenEMR[^=/]+.*v([0-9dev (.-]+)", icase: TRUE );
		}
		if(isnull( ver[1] )){
			url = dir + "/contrib/util/ubuntu_package_scripts/production/changelog.Debian";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req );
			ver = eregmatch( string: buf, pattern: "openemr \\(([^)]+)\\)" );
		}
		if(!isnull( ver[1] )){
			version = ereg_replace( pattern: " \\(", string: ver[1], replace: "-" );
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		cpe = build_cpe( value: version, exp: "^([0-9dev\\.\\-]+)", base: "cpe:/a:open-emr:openemr:" );
		if(!cpe){
			cpe = "cpe:/a:open-emr:openemr";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "OpenEMR", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

