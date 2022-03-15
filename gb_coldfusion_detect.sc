if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100773" );
	script_version( "2021-03-24T09:05:19+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 09:05:19 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2010-09-02 16:10:00 +0200 (Thu, 02 Sep 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Adobe ColdFusion Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Adobe ColdFusion." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
base = "/CFIDE";
file = "/administrator/index.cfm";
url = base + file;
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<title>ColdFusion Administrator Login</title>" ) || ContainsString( res, "ColdFusion" )){
	url = base + "/adminapi/administrator.cfc?method=getBuildNumber";
	req = http_get( item: url, port: port );
	buf = http_send_recv( port: port, data: req, bodyonly: TRUE );
	version = eregmatch( pattern: "([0-9]+,[0-9]+,[0-9]+,[0-9]+)", string: buf );
	if(!isnull( version[1] )){
		cf_version = str_replace( string: version[1], find: ",", replace: "." );
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	if(!cf_version){
		url = base + "/services/pdf.cfc?wsdl";
		req = http_get( item: url, port: port );
		buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( buf, "ColdFusion" )){
			version = eregmatch( pattern: "WSDL created by ColdFusion version ([0-9,]+)-->", string: buf );
			if(!isnull( version[1] )){
				cf_version = str_replace( string: version[1], find: ",", replace: "." );
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	if(!cf_version){
		url = base + "/adminapi/base.cfc?wsdl";
		req = http_get( item: url, port: port );
		buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( buf, "ColdFusion" )){
			version = eregmatch( pattern: "WSDL created by ColdFusion version ([0-9,]+)-->", string: buf );
			if(!isnull( version[1] )){
				cf_version = str_replace( string: version[1], find: ",", replace: "." );
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	if(!cf_version){
		url = base + "/administrator/settings/version.cfm";
		req = http_get( item: url, port: port );
		buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( buf, "ColdFusion" )){
			version = eregmatch( pattern: "Version: ([0-9,hf_]+)</strong>", string: buf );
			if( !isnull( version[1] ) ){
				cf_version = str_replace( string: version[1], find: ",", replace: "." );
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
			else {
				version = eregmatch( pattern: "ColdFusion[^;]+;([0-9]+) Release", string: buf );
				if(!isnull( version[1] )){
					cf_version = str_replace( string: version[1], find: ",", replace: "." );
					concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
	}
	if(!cf_version){
		url = base + "/administrator/help/index.html";
		req = http_get( item: url, port: port );
		buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
		if(ContainsString( buf, "ColdFusion" )){
			version = eregmatch( pattern: "Configuring and Administering ColdFusion ([0-9]+)", string: buf );
			if(!isnull( version[1] )){
				cf_version = version[1];
				concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	if( !cf_version ){
		cf_version = "unknown";
		cpe = "cpe:/a:adobe:coldfusion";
	}
	else {
		cpe = "cpe:/a:adobe:coldfusion:" + cf_version;
	}
	register_product( cpe: cpe, location: url, port: port, service: "www" );
	set_kb_item( name: "adobe/coldfusion/detected", value: TRUE );
	set_kb_item( name: "adobe/coldfusion/http/detected", value: TRUE );
	log_message( data: build_detection_report( app: "Adobe ColdFusion", version: cf_version, install: "/", cpe: cpe, concluded: version[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

