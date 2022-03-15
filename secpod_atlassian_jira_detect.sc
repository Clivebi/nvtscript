if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902046" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Atlassian JIRA Detection" );
	script_tag( name: "summary", value: "Detection of Atlassian JIRA

The script sends a connection request to the server and attempts to detect the presence of Atlassian JIRA
and to extract its version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.atlassian.com/software/jira" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/jira", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( port: port, item: dir + "/login.jsp" );
	if(IsMatchRegexp( rcvRes, "Atlassian JIRA" ) && ContainsString( rcvRes, "/secure/Dashboard.jspa" )){
		version = "unknown";
		vers = eregmatch( pattern: "<meta name=\"ajs-version-number\" content=\"([0-9.]+)\">", string: rcvRes );
		if( !isnull( vers[1] ) ){
			version = vers[1];
		}
		else {
			vers = eregmatch( pattern: "\"footer-build-information\"[^v]+v([0-9.]+)", string: rcvRes );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		set_kb_item( name: "atlassian_jira/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:jira:" );
		if(!cpe){
			cpe = "cpe:/a:atlassian:jira";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Atlassian JIRA", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

