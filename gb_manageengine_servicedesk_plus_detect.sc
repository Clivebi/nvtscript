if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140780" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-16 10:29:54 +0700 (Fri, 16 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ZOHO ManageEngine ServiceDesk Plus Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of ZOHO ManageEngine ServiceDesk Plus.

  The script sends a connection request to the server and attempts to detect ZOHO
  ManageEngine ServiceDesk Plus and to extract its version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>ManageEngine ServiceDesk Plus</title>" ) && ContainsString( res, "j_security_check" )){
	location = "/";
	concluded = "    URL:     " + http_report_vuln_url( port: port, url: location, url_only: TRUE );
	version = eregmatch( string: res, pattern: "ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;\\|&nbsp;&nbsp;([0-9.]+)", icase: TRUE );
	if(isnull( version[1] )){
		version = eregmatch( string: res, pattern: "ManageEngine ServiceDesk Plus','https?://.*','([0-9.]+)'", icase: TRUE );
	}
	if(!isnull( version[1] )){
		concluded += "\n    Version: " + version[0];
		set_kb_item( name: "manageengine/servicedesk_plus/http/" + port + "/version", value: version[1] );
	}
	buildnumber = eregmatch( pattern: "\\.(css|js)\\?([0-9]+)", string: res );
	if(!isnull( buildnumber[2] )){
		concluded += "\n    Build:   " + buildnumber[0];
		set_kb_item( name: "manageengine/servicedesk_plus/http/" + port + "/build", value: buildnumber[2] );
	}
	set_kb_item( name: "manageengine/servicedesk_plus/detected", value: TRUE );
	set_kb_item( name: "manageengine/servicedesk_plus/http/" + port + "/detected", value: TRUE );
	set_kb_item( name: "manageengine/servicedesk_plus/http/" + port + "/location", value: location );
	set_kb_item( name: "manageengine/servicedesk_plus/http/port", value: port );
	set_kb_item( name: "manageengine/servicedesk_plus/http/" + port + "/concluded", value: concluded );
}
exit( 0 );

