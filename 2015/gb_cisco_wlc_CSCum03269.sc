CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105385" );
	script_cve_id( "CVE-2015-0723" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-06-02T09:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2015-09-23 13:59:48 +0200 (Wed, 23 Sep 2015)" );
	script_name( "Cisco Wireless LAN Controller Wireless Web Authentication Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/viewAlert.x?alertId=38749" );
	script_tag( name: "summary", value: "Cisco Wireless LAN Controller contains a vulnerability that could allow an
  unauthenticated, adjacent attacker to cause a denial of service condition. Updates are available." );
	script_tag( name: "impact", value: "An unauthenticated, adjacent attacker could exploit this vulnerability
  to cause a process on an affected device to crash, resulting in a DoS condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists due to improper input sanitization of a certain value
  that is supplied by a user prior to successfully authenticating to an affected device. An attacker could exploit this
  vulnerability by sending a request designed to trigger the vulnerability and cause a process crash that will trigger a
  restart of the device, resulting in a DoS condition." );
	script_tag( name: "solution", value: "Updates are available" );
	script_tag( name: "affected", value: "Cisco WLC versions 7.5.x or versions prior to 7.6.120 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "7.5", test_version2: "7.6.120.0" )){
	if(version_is_less( version: vers, test_version: "7.6.120.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "7.6(120.1)" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

