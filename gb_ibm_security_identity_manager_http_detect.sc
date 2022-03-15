if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108817" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-12 17:05:24 +0530 (Tue, 12 Jun 2018)" );
	script_name( "IBM Security Identity Manager Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443, 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of the IBM Security Identity Manager." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
url = "/itim/self/jsp/logon/login.jsp";
res = http_get_cache( item: url, port: port );
url2 = "/login";
res2 = http_get_cache( item: url2, port: port );
if( ContainsString( res, "<title>IBM Security Identity Manager</title>" ) || ContainsString( res, "alt=\"IBM Security Identity Manager" ) || ContainsString( res, "title=\"IBM Security Identity Manager" ) ){
	found = TRUE;
	conclurl = http_report_vuln_url( url: url, port: port, url_only: TRUE );
}
else {
	if(ContainsString( res2, "<title>IBM Security Identity Manager</title>" ) || ContainsString( res2, "alt=\"IBM Security Identity Manager" ) || ContainsString( res2, "title=\"IBM Security Identity Manager" )){
		found = TRUE;
		conclurl = http_report_vuln_url( url: url2, port: port, url_only: TRUE );
	}
}
if(found){
	version = "unknown";
	install = "/";
	set_kb_item( name: "ibm/security_identity_manager/detected", value: TRUE );
	set_kb_item( name: "ibm/security_identity_manager/http/detected", value: TRUE );
	set_kb_item( name: "ibm/security_identity_manager/http/port", value: port );
	vers = eregmatch( pattern: "IBM Security Identity Manager v([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: "IBM Security Identity Manager v([0-9.]+)", string: res2 );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	if(version == "unknown"){
		vers = eregmatch( pattern: "cacheBust: \"([0-9.]+)\"", string: res2 );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	set_kb_item( name: "ibm/security_identity_manager/http/" + port + "/installs", value: port + "#---#" + install + "#---#" + version + "#---#" + vers[0] + "#---#" + conclurl );
}
exit( 0 );

