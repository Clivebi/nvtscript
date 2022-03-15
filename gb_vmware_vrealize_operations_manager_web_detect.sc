if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105862" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-08-11 15:53:38 +0200 (Thu, 11 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "VMware vRealize Operations Manager Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of VMware vRealize Operations Manager." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.vmware.com/products/vrealize-operations.html" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 443 );
url = "/admin/login.action";
buf = http_get_cache( item: url, port: port );
if(!ContainsString( buf, "<title>vRealize Operations Manager" )){
	url = "/ui/#/login";
	buf = http_get_cache( item: url, port: port );
}
if(IsMatchRegexp( buf, "<title>vRealize Operations( Manager)?" )){
	api_url = "/suite-api/api/versions/current";
	req = http_get( item: api_url, port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(!ContainsString( res, "ops:version" ) || !ContainsString( res, "VMware vRealize Operations Manager" )){
		exit( 0 );
	}
	cpe = "cpe:/a:vmware:vrealize_operations_manager";
	vers = "unknown";
	rep_vers = vers;
	set_kb_item( name: "vmware/vrealize/operations_manager/installed", value: TRUE );
	version = eregmatch( pattern: "<ops:releaseName>VMware vRealize Operations Manager ([0-9.]+[^<]+)</ops:releaseName>", string: res );
	if(!isnull( version[1] )){
		vers = version[1];
		rep_vers = vers;
		cpe += ":" + vers;
		set_kb_item( name: "vmware/vrealize/operations_manager/version", value: vers );
	}
	b = eregmatch( pattern: "<ops:buildNumber>([0-9]+[^<]+)</ops:buildNumber>", string: res );
	if(!isnull( b[1] )){
		build = b[1];
		rep_vers += " (Build: " + build + ")";
		set_kb_item( name: "vmware/vrealize/operations_manager/build", value: build );
	}
	os_register_and_report( os: "VMware Photon OS", cpe: "cpe:/o:vmware:photonos", desc: "VMware vRealize Operations Manager Detection (HTTP)", runs_key: "unixoide" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	report = build_detection_report( app: "VMware vRealize Operations Manager", version: rep_vers, install: "/", cpe: cpe, concluded: res, concludedUrl: http_report_vuln_url( port: port, url: api_url, url_only: TRUE ) );
	log_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

