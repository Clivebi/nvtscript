if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801453" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)" );
	script_cve_id( "CVE-2009-4994", "CVE-2009-4995" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "SmarterTools SmarterTrack Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36172" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/52305" );
	script_xref( name: "URL", value: "http://holisticinfosec.org/content/view/123/45/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9996 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "insight", value: "The flaws are due to the input passed to the 'search' parameter in
  'frmKBSearch.aspx' and email address to 'frmTickets.aspx' is not properly
  sanitised before being returned to the user." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to SmarterTools SmarterTrack version 4.0.3504." );
	script_tag( name: "summary", value: "This host is running SmarterTools SmarterTrack and is prone
  Cross-site scripting vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "SmarterTools SmarterTrack version prior to 4.0.3504." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 9996 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
res = http_get_cache( item: "/Main/Default.aspx", port: port );
if(!res || !ContainsString( res, ">SmarterTrack" )){
	exit( 0 );
}
url = "/Main/frmKBSearch.aspx?search=%3Cscript%3Ealert(%22VT-XSS-Test%22)%3C/script%3E";
req = http_get( port: port, item: url );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "<script>alert(\"VT-XSS-Test\")</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

