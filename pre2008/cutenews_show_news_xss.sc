CPE = "cpe:/a:cutephp:cutenews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12291" );
	script_version( "$Revision: 13679 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2004-0660" );
	script_bugtraq_id( 10620, 10750 );
	script_xref( name: "OSVDB", value: "7283" );
	script_xref( name: "OSVDB", value: "7284" );
	script_xref( name: "OSVDB", value: "7285" );
	script_xref( name: "OSVDB", value: "7286" );
	script_name( "CuteNews show_news.php XSS" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_copyright( "This script is Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "cutenews_detect.sc", "cross_site_scripting.sc" );
	script_mandatory_keys( "cutenews/installed" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "The remote web server contains several PHP scripts that are prone to
cross-site scripting attacks.

Description :

The installed version of CuteNews is vulnerable to cross-site scripting attacks.  An attacker may use this bug to
steal the credentials of legitimate users of this site." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/367289" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
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
req = http_get( item: NASLString( dir, "/show_news.php?subaction=showcomments&id=%3Cscript%3Efoo%3C/script%3E&archive=&start_from=&ucat=" ), port: port );
r = http_keepalive_send_recv( port: port, data: req );
if(isnull( r )){
	exit( 0 );
}
if(IsMatchRegexp( r, "^HTTP/1\\.[01] 200" ) && ContainsString( r, "<script>foo</script>" )){
	security_message( port );
	exit( 0 );
}
exit( 99 );

