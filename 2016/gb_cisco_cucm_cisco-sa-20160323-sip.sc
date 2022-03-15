CPE = "cpe:/a:cisco:unified_communications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105595" );
	script_cve_id( "CVE-2016-1350" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "$Revision: 12338 $" );
	script_name( "Cisco Unified Communications Manager Software Session Initiation Protocol Memory Leak Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip" );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a memory leak and eventual reload of the affected device." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to improper processing of malformed SIP messages.  An attacker could exploit this vulnerability by sending malformed SIP messages to be processed by an affected device." );
	script_tag( name: "solution", value: "Update to 9.1(2)su4/10.5(2)su3/11.0(1)su1 or newer." );
	script_tag( name: "summary", value: "A vulnerability in the Session Initiation Protocol (SIP) gateway implementation in Cisco Unified Communications Manager Software could allow an unauthenticated, remote attacker to cause a memory leak and eventual reload of an affected device." );
	script_tag( name: "affected", value: "Cisco Unified Communications Manager 8.x and < 9.1(2)su4/10.5(2)su3/11.0(1)su1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-04-04 12:02:56 +0200 (Mon, 04 Apr 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_cucm_version.sc" );
	script_mandatory_keys( "cisco/cucm/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
vers = str_replace( string: vers, find: "-", replace: "." );
if(IsMatchRegexp( vers, "^8\\." )){
	fix = "9.1(2)su4";
}
if(version_in_range( version: vers, test_version: "9", test_version2: "9.1.2.10000.28" )){
	fix = "9.1(2)su4";
}
if(version_in_range( version: vers, test_version: "10", test_version2: "10.5.2.10000.5" )){
	fix = "10.5(2)su3";
}
if(version_in_range( version: vers, test_version: "11", test_version2: "11.0.1.10000.10" )){
	fix = "11.0(1)su1";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

