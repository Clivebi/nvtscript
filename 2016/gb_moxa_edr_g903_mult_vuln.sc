CPE = "cpe:/h:moxa:edr-g903";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808220" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-0875", "CVE-2016-0876", "CVE-2016-0877", "CVE-2016-0878", "CVE-2016-0879" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-06-09 13:45:38 +0530 (Thu, 09 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_name( "Moxa EDR G903 Router Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Moxa EDR G903
  Router and is prone to multiple vulnerabilities" );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to access sensitive data." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The copies of configuration and log files are not deleted after completing
    the import function.

  - The configuration and log files can be accessed without authentication.

  - An improper validation of 'ping' function." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to obtain sensitive information by accessing sensitive files
  and also to cause a denial of service (memory consumption)." );
	script_tag( name: "affected", value: "Moxa EDR-G903 Versions V3.4.11 and older." );
	script_tag( name: "solution", value: "Upgrade to firmware version v3.4.12 or
  later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-042-01" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moxa_edr_g903_remote_detect.sc" );
	script_mandatory_keys( "Moxa/EDR/G903/Installed" );
	script_require_ports( "Services/www", 80 );
	script_xref( name: "URL", value: "http://www.moxa.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!edrPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/xml/net_led_xml";
if(http_vuln_check( port: edrPort, url: url, check_header: TRUE, pattern: "<eth[0-9]>[0-9.]+</eth[0-9]>", extra_check: "<thermal>" )){
	report = http_report_vuln_url( port: edrPort, url: url );
	security_message( port: edrPort, data: report );
	exit( 0 );
}
exit( 0 );

