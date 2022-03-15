CPE = "cpe:/h:building_automation_systems:bas";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812372" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2017-17974" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-01-03 11:58:58 +0530 (Wed, 03 Jan 2018)" );
	script_name( "Building Automation Systems BAS920 Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "The host is running Building Automation Systems
  BAS920 and is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends the crafted http GET request
  and checks whether it is able to read the sensitive information or not." );
	script_tag( name: "insight", value: "The flaw exists due to improper access control
  mechanisms in the device." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "BA SYSTEMS BAS Web on BAS920 devices with
  Firmware 01.01.00*, HTTPserv 00002, and Script 02.*. Other models may be also
  affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "http://misteralfa-hack.blogspot.in/2017/12/ba-system-improper-access-control.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ba_systems_web_detect.sc" );
	script_mandatory_keys( "BAS/Device/Installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!basPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
get_app_location( cpe: CPE, port: basPort, nofork: TRUE );
url = "/isc/get_sid_js.aspx";
if(http_vuln_check( port: basPort, url: url, pattern: "\"name\":\"", extra_check: make_list( "\"pass\":\"",
	 "\"sid\":",
	 "\"email\":" ), check_header: TRUE )){
	report = http_report_vuln_url( port: basPort, url: url );
	security_message( port: basPort, data: report );
	exit( 0 );
}
exit( 99 );

