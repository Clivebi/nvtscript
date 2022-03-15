CPE = "cpe:/a:ez:ez_publish";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11449" );
	script_version( "$Revision: 13679 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 7137, 7138 );
	script_cve_id( "CVE-2003-0310" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "eZ Publish Cross Site Scripting Bugs" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2003 k-otik.com" );
	script_dependencies( "sw_ez_publish_detect.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ez_publish/installed" );
	script_tag( name: "solution", value: "Upgrade to a newer version." );
	script_tag( name: "summary", value: "eZ Publish 2.2.7  has a cross site scripting bug. An attacker may use it to
 perform a cross site scripting attack on this host.

 In addition to this, another flaw may allow an attacker store hostile
 HTML code on the server side, which will be executed by the browser of the
 administrative user when he looks at the server logs." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
host = http_host_name( dont_add_port: TRUE );
if(http_get_has_generic_xss( port: port, host: host )){
	exit( 0 );
}
url = NASLString( dir, "/search/?SectionIDOverride=1&SearchText=<script>window.alert(document.cookie);</script>" );
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req );
if(isnull( buf )){
	exit( 0 );
}
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<script>window.alert(document.cookie);</script>" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

