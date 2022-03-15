if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12227" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9973 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "HP Jet Admin 6.5 or less Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 facq" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "The issues are resolved in HP Web Jetadmin version 7.5" );
	script_tag( name: "summary", value: "The remote HP Web Jetadmin is vulnerable to multiple exploits.  This includes,
  but is not limited to, full remote administrative access." );
	script_tag( name: "impact", value: "An attacker can execute code remotely with SYSTEM level (or root) privileges by
  invoking the ExecuteFile function. To further exacerbate this issue, there is working exploit code for multiple
  vulnerabilities within this product." );
	script_xref( name: "URL", value: "http://www.phenoelit.de/stuff/HP_Web_Jetadmin_advisory.txt" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/15989" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 8000;
if(!get_port_state( port )){
	exit( 0 );
}
url = "/plugins/hpjwja/help/about.hts";
r = http_send_recv( port: port, data: NASLString( "GET ", url, " HTTP/1.0\\r\\n\\r\\n" ) );
if(!r){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1.[01] 200" ) && ContainsString( r, "Server: HP-Web-Server" )){
	r = ereg_replace( pattern: "<b>|</b>", string: r, replace: "<>" );
	r = ereg_replace( pattern: "<[^>]+>", string: r, replace: "" );
	r = ereg_replace( pattern: "[[:space:]]+", string: r, replace: " " );
	r = ereg_replace( pattern: " <>", string: r, replace: "<>" );
	r = ereg_replace( pattern: "<> ", string: r, replace: "<>" );
	if(IsMatchRegexp( r, "<>HP Web JetAdmin Version<>6.5" ) || IsMatchRegexp( r, "<>HP Web JetAdmin Version<>6.2" ) || IsMatchRegexp( r, "<>HP Web JetAdmin Version<>7.0" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
	}
	exit( 99 );
}
exit( 0 );

