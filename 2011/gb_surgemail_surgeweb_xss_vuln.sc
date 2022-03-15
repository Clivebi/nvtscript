if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801808" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-01-18 07:48:41 +0100 (Tue, 18 Jan 2011)" );
	script_cve_id( "CVE-2010-3201" );
	script_bugtraq_id( 43679 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "SurgeMail SurgeWeb Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://ictsec.se/?p=108" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41685" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/514115/100/0/threaded" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "surgemail/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary HTML and
  script code, which will be executed in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "NetWin Surgemail versions before 4.3g." );
	script_tag( name: "insight", value: "The flaw is caused by improper validation of user-supplied input via the
  'username_ex' parameter to the SurgeWeb interface '/surgeweb', which allows
  the attackers to execute arbitrary HTML and script code in a user's browser
  session in the context of an affected site." );
	script_tag( name: "solution", value: "Upgrade to NetWin Surgemail version 4.3g or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running SurgeMail and is prone to Cross site scripting
  vulnerability." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(banner && ContainsString( banner, "surgemail" )){
	url = "/surgeweb?username_ex=\"/><script>alert(\'VT-XSS-Test\')</script>";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('VT-XSS-Test'\\)</script>", check_header: TRUE )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
	}
}

