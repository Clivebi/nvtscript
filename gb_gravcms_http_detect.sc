if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112826" );
	script_version( "2020-09-24T12:59:47+0000" );
	script_tag( name: "last_modification", value: "2020-09-24 12:59:47 +0000 (Thu, 24 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-09-24 12:00:00 +0000 (Thu, 24 Sep 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grav CMS Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Grav CMS." );
	script_xref( name: "URL", value: "https://getgrav.org/" );
	exit( 0 );
}
CPE = "cpe:/a:getgrav:gravcms:";
require("host_details.inc.sc");
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/admin", port: port );
if(IsMatchRegexp( buf, "HTTP/1\\.[01] 200" ) && ContainsString( buf, "<title>Grav Admin Login" ) && ContainsString( buf, "this.GravAdmin = this.GravAdmin" )){
	set_kb_item( name: "getgrav/gravcms/detected", value: TRUE );
	version = "unknown";
	if( vers = eregmatch( pattern: "\"message\":\"Grav v([0-9a-z.-]+)\",", string: buf ) ){
		if(!isnull( vers[1] )){
			version = vers[1];
			concluded = http_report_vuln_url( port: port, url: "/admin", url_only: TRUE );
		}
	}
	else {
		buf = http_get_cache( port: port, item: "/CHANGELOG.md" );
		if(vers = eregmatch( pattern: "# v([0-9a-z.\\-]+)", string: buf )){
			if(!isnull( vers[1] )){
				version = vers[1];
				concluded = http_report_vuln_url( port: port, url: "/CHANGELOG.md", url_only: TRUE );
			}
		}
	}
	register_and_report_cpe( app: "Grav CMS", ver: version, concluded: vers[0], base: CPE, expr: "([0-9.]+)", insloc: "/", conclUrl: concluded, regPort: port, regService: "www" );
	exit( 0 );
}
exit( 0 );

