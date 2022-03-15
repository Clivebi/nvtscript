if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140195" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-17 16:36:11 +0100 (Fri, 17 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "GitHub Enterprise WebGUI / Management Console Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8443, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of the GitHub Enterprise
  WebGUI or Management Console." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8443 );
for dir in make_list( "/login",
	 "/setup/unlock" ) {
	detected = FALSE;
	version = "unknown";
	conclUrl = http_report_vuln_url( port: port, url: dir, url_only: TRUE );
	buf = http_get_cache( item: dir, port: port );
	if(!buf || ( !IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && !IsMatchRegexp( buf, "^HTTP/1\\.[01] 402 Payment Required" ) )){
		continue;
	}
	if( IsMatchRegexp( buf, "<title>(Setup )?GitHub Enterprise( preflight check)?</title>" ) || ContainsString( buf, "Please enter your password to unlock the GitHub Enterprise management" ) || ContainsString( buf, "GitHub Enterprise requires one of the following" ) || ContainsString( buf, "enterprise.github.com/support\">contact support" ) ){
		app_name = "GitHub Enterprise Management Console";
		install = "/setup";
		detected = TRUE;
		set_kb_item( name: "github/enterprise/management_console/detected", value: TRUE );
	}
	else {
		if(( IsMatchRegexp( buf, "<title>GitHub . Enterprise</title>" ) && ContainsString( buf, "<meta name=\"description\" content=\"GitHub is where people build software." ) ) || IsMatchRegexp( buf, "<img alt=\"GitHub Enterprise logo\" src=\".*/images/modules/enterprise/gh-enterprise-logo.svg\"" ) || ( ContainsString( buf, "Sorry, your GitHub Enterprise license expired" ) && ContainsString( buf, "<h1>License Expired</h1>" ) )){
			vers = eregmatch( pattern: "<a href=\"https://help.github.com/enterprise/([0-9.]+)\"", string: buf );
			if(vers[1]){
				version = vers[1];
			}
			app_name = "GitHub Enterprise WebGUI";
			install = "/";
			detected = TRUE;
			set_kb_item( name: "github/enterprise/webgui/detected", value: TRUE );
		}
	}
	if(detected){
		register_and_report_cpe( app: app_name, ver: version, concluded: vers[0], conclUrl: conclUrl, base: "cpe:/a:github:github_enterprise:", expr: "^([0-9.]+)", regPort: port, regService: "www", insloc: install );
	}
}
exit( 0 );

