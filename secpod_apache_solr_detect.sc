if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903506" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2014-01-29 13:13:35 +0530 (Wed, 29 Jan 2014)" );
	script_name( "Apache Solr Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8983 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://lucene.apache.org/solr/" );
	script_tag( name: "summary", value: "HTTP based detection of Apache Solr." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8983 );
for dir in nasl_make_list_unique( "/", "/solr", "/apachesolr", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/", port: port );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ( ContainsString( res, ">Solr Admin<" ) || ContainsString( res, "Solr admin page" ) || ContainsString( res, "ng-app=\"solrAdminApp\"" ) )){
		set_kb_item( name: "apache/solr/detected", value: TRUE );
		version = "unknown";
		url = dir + "/admin/info/system";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( pattern: "(solr-spec-version\">|\"solr-spec-version\":\")([0-9.]+)", string: res );
		if(!isnull( vers[2] )){
			version = vers[2];
			concurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(version == "unknown"){
			url = dir + "/#/";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( string: res, pattern: "(js/require\\.js|img/favicon\\.ico)\\?_=([0-9.]+)", icase: TRUE );
			if(!isnull( vers[2] )){
				version = vers[2];
				concurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		if(version == "unknown"){
			url = dir + "/admin/registry.jsp";
			req = http_get( item: url, port: port );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( string: res, pattern: "solr-spec-version>([0-9.]+)", icase: TRUE );
			if(!isnull( vers[1] )){
				version = vers[1];
				concurl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:apache:solr:" );
		if(!cpe){
			cpe = "cpe:/a:apache:solr";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Apache Solr", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concurl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

