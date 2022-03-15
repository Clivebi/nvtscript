if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108760" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-29 07:29:36 +0000 (Wed, 29 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Cloudflare '/cdn-cgi/trace' Debug / Trace Output Accessible" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is exposing the '/cdn-cgi/trace' endpoint of
  Cloudflare." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/cdn-cgi/trace";
buf = http_get_cache( item: url, port: port );
if(buf && IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "content-type\\s*:\\s*text/plain" ) && egrep( string: buf, pattern: "^visit_scheme=.+", icase: FALSE )){
	report = "Exposed URL: " + http_report_vuln_url( port: port, url: url, url_only: TRUE );
	log_message( port: port, data: report );
}
exit( 0 );

