CPE = "cpe:/a:cisco:firepower_management_center";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106235" );
	script_cve_id( "CVE-2016-6394" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "2020-04-03T09:54:35+0000" );
	script_name( "Cisco Firepower Management Center Session Fixation Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160907-fsmc" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 6.1.0.1 or later." );
	script_tag( name: "summary", value: "A vulnerability in session identification management functionality of the
  web-based management interface for Cisco FireSIGHT System Software could allow an unauthenticated, remote
  attacker to hijack a valid user session." );
	script_tag( name: "insight", value: "The vulnerability exists because the affected application does not assign
  a new session identifier to a user session when a user authenticates to the application. An attacker could
  exploit this vulnerability by using a hijacked session identifier to connect to the application through the
  web-based management interface." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to hijack an authenticated
  user's browser session." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "last_modification", value: "2020-04-03 09:54:35 +0000 (Fri, 03 Apr 2020)" );
	script_tag( name: "creation_date", value: "2016-09-08 10:11:15 +0700 (Thu, 08 Sep 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_firepower_management_center_consolidation.sc" );
	script_mandatory_keys( "cisco/firepower_management_center/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "6.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1.0.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

