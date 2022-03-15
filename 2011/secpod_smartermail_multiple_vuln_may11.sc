CPE = "cpe:/a:smartertools:smartermail";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902432" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-06-01 11:16:16 +0200 (Wed, 01 Jun 2011)" );
	script_cve_id( "CVE-2011-2148", "CVE-2011-2149", "CVE-2011-2150", "CVE-2011-2151", "CVE-2011-2152", "CVE-2011-2153", "CVE-2011-2154", "CVE-2011-2155", "CVE-2011-2156", "CVE-2011-2157", "CVE-2011-2158", "CVE-2011-2159" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "SmarterMail Multiple Vulnerabilities May-11" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/240150" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/MORO-8GYQR4" );
	script_xref( name: "URL", value: "http://xss.cx/examples/smarterstats-60-oscommandinjection-directorytraversal-xml-sqlinjection.html.html" );
	script_xref( name: "URL", value: "http://www.smartertools.com/smartermail/mail-server-software.aspx" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_smartermail_detect.sc" );
	script_require_ports( "Services/www", 80, 9998 );
	script_mandatory_keys( "SmarterMail/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to conduct cross site scripting,
  command execution and directory traversal attacks." );
	script_tag( name: "affected", value: "SmarterTools SmarterMail versions 6.0 and prior." );
	script_tag( name: "solution", value: "Upgrade to SmarterTools SmarterMail 8.0 or later." );
	script_tag( name: "summary", value: "This host is running SmarterMail and is prone to multiple
  vulnerabilities." );
	script_tag( name: "insight", value: "Multiple flaws are present in the application. More detail is available from the referenced advisory." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!smPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/Login.aspx?shortcutLink=autologin&txtSiteID" + "=admin&txtUser=admin&txtPass=admin";
sndReq = http_get( item: url, port: smPort );
rcvRes = http_keepalive_send_recv( port: smPort, data: sndReq );
if(ContainsString( rcvRes, "txtUser=admin&" ) && ContainsString( rcvRes, "txtPass=admin" )){
	report = http_report_vuln_url( port: smPort, url: url );
	security_message( port: smPort, data: report );
	exit( 0 );
}
exit( 99 );

