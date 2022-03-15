if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106738" );
	script_version( "2021-07-14T08:39:56+0000" );
	script_tag( name: "last_modification", value: "2021-07-14 08:39:56 +0000 (Wed, 14 Jul 2021)" );
	script_tag( name: "creation_date", value: "2017-04-10 14:46:29 +0200 (Mon, 10 Apr 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Kaseya VSA Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Kaseya VSA." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.kaseya.com/products/vsa" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
header = make_array( "Referer", "https://" + get_host_name() + "/" );
url = "/vsapres/web20/core/login.aspx";
req = http_get_req( port: port, url: url, add_headers: header );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "logoforLogin.gif" ) && ContainsString( res, "/vsapres/js/kaseya/web/bootstrap.js" ) && ContainsString( res, "Kaseya" )){
	version = "unknown";
	vers = eregmatch( pattern: "SystemVersionItem.*<span>([0-9.]+)</span>", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	patchlevel = eregmatch( pattern: "PatchLevelItem[^<]+<br />[^<]+<span>([0-9.]+)</span>", string: res );
	if(!isnull( patchlevel[1] )){
		set_kb_item( name: "kaseya_vsa/patchlevel", value: patchlevel[1] );
		extra = "Patch Level:  " + patchlevel[1];
	}
	set_kb_item( name: "kaseya_vsa/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kaseya:virtual_system_administrator:" );
	if(!cpe){
		cpe = "cpe:/a:kaseya:virtual_system_administrator";
	}
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", desc: "Kaseya VSA Detection (HTTP)", runs_key: "windows" );
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Kaseya VSA", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

