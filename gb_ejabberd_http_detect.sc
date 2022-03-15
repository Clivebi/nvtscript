if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144096" );
	script_version( "2021-05-14T13:11:51+0000" );
	script_tag( name: "last_modification", value: "2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)" );
	script_tag( name: "creation_date", value: "2020-06-09 08:32:21 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ejabberd Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of ejabberd." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5280 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 5280 );
url = "/admin/doc/README.txt";
res = http_get_cache( port: port, item: url );
if(( ContainsString( res, "Release Notes" ) && ContainsString( res, "ejabberd" ) ) || ( IsMatchRegexp( res, "^HTTP/1\\.[01] 401" ) && ContainsString( res, "WWW-Authenticate: basic realm=\"ejabberd\"" ) )){
	version = "unknown";
	set_kb_item( name: "ejabberd/detected", value: TRUE );
	set_kb_item( name: "ejabberd/http/port", value: port );
	vers = eregmatch( string: res, pattern: "ejabberd ([0-9.]+)", icase: TRUE );
	if(!isnull( vers[1] )){
		version = vers[1];
		set_kb_item( name: "ejabberd/http/" + port + "/concluded", value: vers[0] );
		set_kb_item( name: "ejabberd/http/" + port + "/concludedUrl", value: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
	}
	set_kb_item( name: "ejabberd/http/" + port + "/version", value: version );
}
exit( 0 );

