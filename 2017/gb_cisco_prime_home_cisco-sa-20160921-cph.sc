CPE = "cpe:/a:cisco:prime_home";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140150" );
	script_cve_id( "CVE-2016-6408" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_name( "Cisco Prime Home Web-Based User Interface XML External Entity Vulnerability" );
	script_tag( name: "insight", value: "The vulnerability is due to improper handling of an XML External
  Entity (XXE) when parsing an XML file. An attacker could exploit this vulnerability by sending a
  crafted XML file to the affected system." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to 5.2.1.2 or later." );
	script_tag( name: "summary", value: "A vulnerability in the web-based user interface of Cisco Prime Home
  could allow an unauthenticated, remote attacker to have read access to part of the information stored
  in the affected system." );
	script_tag( name: "affected", value: "Cisco Prime Home 5.2 < 5.2.1.2." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:32:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "creation_date", value: "2017-02-02 16:06:02 +0100 (Thu, 02 Feb 2017)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_prime_home_web_detect.sc" );
	script_mandatory_keys( "cisco/prime_home/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "5.2", test_version2: "5.2.1.1" )){
	fix = "5.2.1.2";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

