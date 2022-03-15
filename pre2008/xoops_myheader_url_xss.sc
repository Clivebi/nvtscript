CPE = "cpe:/a:xoops:xoops";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11962" );
	script_version( "2020-05-08T11:13:33+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 11:13:33 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 9269 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "XOOPS myheader.php URL Cross Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xoops_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "XOOPS/installed" );
	script_tag( name: "solution", value: "Upgrade to the latest version of XOOPS." );
	script_tag( name: "summary", value: "The weblinks module of XOOPS contains a file named 'myheader.php'
  in /modules/mylinks/ directory. The code of the module insufficiently
  filters out user provided data." );
	script_tag( name: "impact", value: "The URL parameter used by 'myheader.php'
  can be used to insert malicious HTML and/or JavaScript in to the web page." );
	script_tag( name: "affected", value: "XOOPS 2.0.5.1 is known to be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
expRes = raw_string( 0x22 );
expRes = NASLString( "href=", expRes, "javascript:foo", expRes );
url = dir + "/modules/mylinks/myheader.php?url=javascript:foo";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, expRes )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

