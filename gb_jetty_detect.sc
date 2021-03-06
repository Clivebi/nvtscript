if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800953" );
	script_version( "2021-03-01T15:58:40+0000" );
	script_tag( name: "last_modification", value: "2021-03-01 15:58:40 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "MortBay / Eclipse Jetty Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.eclipse.org/jetty/" );
	script_tag( name: "summary", value: "HTTP based detection of MortBay / Eclipse Jetty." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
func jetty_extract_version( ver ){
	var ver;
	var version;
	if(!isnull( ver[1] )){
		if( !isnull( ver[2] ) ){
			ver[2] = ereg_replace( pattern: "^v", string: ver[2], replace: "" );
			if( IsMatchRegexp( ver[1], "\\.$" ) ) {
				version = ver[1] + ver[2];
			}
			else {
				version = ver[1] + "." + ver[2];
			}
		}
		else {
			ver[1] = ereg_replace( pattern: "\\.$", string: ver[1], replace: "" );
			version = ver[1];
		}
	}
	return version;
}
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(_banner = egrep( pattern: "^Server: (MortBay-)?Jetty", string: banner, icase: TRUE )){
	version = "unknown";
	installed = TRUE;
	concluded = _banner;
	ver = eregmatch( pattern: "Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string: _banner );
	_ver = jetty_extract_version( ver: ver );
	if(_ver){
		version = _ver;
	}
}
if(!installed){
	for url in make_list( "/",
		 "/vt-test-non-existent.html",
		 "/vt-test/vt-test-non-existent.html" ) {
		res = http_get_cache( item: url, port: port, fetch404: TRUE );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] [1-5][0-9]{2}" ) && ( IsMatchRegexp( res, ">Powered by Jetty://" ) || egrep( pattern: "^Server: (MortBay-)?Jetty", string: res, icase: TRUE ) )){
			installed = TRUE;
			version = "unknown";
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			ver = eregmatch( pattern: ">Powered by Jetty:// ([0-9.]+)([a-zA-Z]+[0-9]+)?[^<]*", string: res );
			if(!ver){
				ver = eregmatch( pattern: "Jetty.([0-9.]+)([a-zA-Z]+[0-9]+)?", string: res );
			}
			_ver = jetty_extract_version( ver: ver );
			if(_ver){
				version = _ver;
				concluded = ver[0];
			}
			break;
		}
	}
}
if(installed){
	install = port + "/tcp";
	set_kb_item( name: "jetty/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:eclipse:jetty:" );
	if(!cpe){
		cpe = "cpe:/a:eclipse:jetty";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "MortBay / Eclipse Jetty", version: version, install: install, cpe: cpe, concluded: concluded, concludedUrl: conclUrl ), port: port );
}
exit( 0 );

