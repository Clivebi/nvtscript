if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108001" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-09-15 09:00:00 +0200 (Thu, 15 Sep 2016)" );
	script_name( "OpenCA Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of OpenCA.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
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
for dir in nasl_make_list_unique( "/cgi-bin", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	for url in make_list( dir + "/pub/pki?cmd=serverInfo",
		 dir + "/pki/pub/pki?cmd=serverInfo" ) {
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
		if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ( ContainsString( buf, "Server Information for" ) && ContainsString( buf, "OpenCA" ) ) || ContainsString( buf, "http://www.openca.org" ) || ContainsString( buf, "OpenCA Labs" ) || ContainsString( buf, "document.OPENCA" ) )){
			version = "unknown";
			concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			ver = eregmatch( string: buf, pattern: "Version ([0-9rc.-]+)</title>", icase: TRUE );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
			tmp_version = version + " under " + install;
			set_kb_item( name: "www/" + port + "/openca", value: tmp_version );
			set_kb_item( name: "openca/installed", value: TRUE );
			cpe = build_cpe( value: version, exp: "^([0-9rc.-]+)", base: "cpe:/a:openca:openca:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:openca:openca";
			}
			register_product( cpe: cpe, location: install, port: port, service: "www" );
			log_message( data: build_detection_report( app: "OpenCA", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concludedUrl ), port: port );
		}
	}
}
exit( 0 );

