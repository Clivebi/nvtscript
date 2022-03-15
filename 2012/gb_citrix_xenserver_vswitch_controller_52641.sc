if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103474" );
	script_bugtraq_id( 52641 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_name( "Citrix XenServer vSwitch Controller Component Multiple Vulnerabilities" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-23 11:36:51 +0200 (Mon, 23 Apr 2012)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52641" );
	script_xref( name: "URL", value: "http://www.citrix.com/English/ps2/products/feature.asp?contentID=1686939" );
	script_xref( name: "URL", value: "http://support.citrix.com/article/CTX132476" );
	script_tag( name: "summary", value: "Citrix XenServer is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "impact", value: "The impact of these issues is currently unknown." );
	script_tag( name: "affected", value: "Citrix XenServer versions 5.6, 5.6 FP 1, 5.6 SP 2, and 6 are
  vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( buf, "DVSC_MGMT_UI_SESSION" ) && !IsMatchRegexp( buf, "<title>.*DVS.*Controller" )){
		continue;
	}
	url = dir + "/static/";
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req );
	if(!ContainsString( buf, "Directory listing for /static" )){
		continue;
	}
	lines = split( buf );
	locs = make_list();
	for line in lines {
		if(locs = eregmatch( pattern: "<a href=\"([0-9]+)/\">", string: line )){
			loc[i++] = locs[1];
		}
	}
	for l in loc {
		url = "/static/" + l + "/nox/ext/apps/vmanui/main.js";
		req = http_get( item: url, port: port );
		buf = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( buf, "dojo.provide(\"nox.ext.apps.vmanui.main\")" )){
			if(!ContainsString( buf, "X-CSRF-Token" ) && !ContainsString( buf, "oCsrfToken" )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

