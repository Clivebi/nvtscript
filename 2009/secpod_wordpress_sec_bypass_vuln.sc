CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900913" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2762" );
	script_bugtraq_id( 36014 );
	script_name( "WordPress wp-login.php Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9410" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52382" );
	script_xref( name: "URL", value: "http://wordpress.org/development/2009/08/2-8-4-security-release/" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wordpress/installed" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to bypass security restrictions and change
  the administrative password." );
	script_tag( name: "affected", value: "WordPress version prior to 2.8.4 on all running platform." );
	script_tag( name: "insight", value: "The flaw is due to an error in the wp-login.php script password reset
  mechanism which can be exploited by passing an array variable in a resetpass (aka rp) action." );
	script_tag( name: "solution", value: "Update to Version 2.8.4 or later." );
	script_tag( name: "summary", value: "The host is running WordPress and is prone to a Security Bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
if(!wpPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: wpPort )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = NASLString( dir, "/wp-login.php?action=rp&key[]=" );
sndReq = http_get( item: url, port: wpPort );
rcvRes = http_send_recv( port: wpPort, data: sndReq );
if(ContainsString( rcvRes, "checkemail=newpass" )){
	report = http_report_vuln_url( port: wpPort, url: url );
	security_message( port: wpPort, data: report );
	exit( 0 );
}
exit( 99 );

