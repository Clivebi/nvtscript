CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105741" );
	script_cve_id( "CVE-2016-1364" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-06-02T09:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-06-01 11:50:17 +0200 (Wed, 01 Jun 2016)" );
	script_name( "Cisco Wireless LAN Controller Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-bdos" );
	script_tag( name: "summary", value: "A vulnerability in the Bonjour task manager of Cisco Wireless LAN Controller (WLC) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending crafted Bonjour traffic to an affected device. A successful exploit could allow the attacker to cause the device to reload, resulting in a DoS condition." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "affected", value: "All 7.4 releases prior to 7.4.130.0(MD), all 7.5 releases,
  all 7.6 releases and all 8.0 releases prior to 8.0.110.0(ED)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "CISCO" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^7\\.[56]" )){
	fix = "8.0.132.0";
}
if(IsMatchRegexp( vers, "^7\\.4" )){
	if(version_is_less( version: vers, test_version: "7.4.130.0" )){
		fix = "7.4.130(MD)";
	}
}
if(IsMatchRegexp( vers, "^8\\.0" )){
	if(version_is_less( version: vers, test_version: "8.0.110.0" )){
		fix = "8.0.110.0";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

