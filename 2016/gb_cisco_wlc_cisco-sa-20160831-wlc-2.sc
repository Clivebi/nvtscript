CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106219" );
	script_version( "2021-06-02T09:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-09-01 14:58:40 +0700 (Thu, 01 Sep 2016)" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2016-6376" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Wireless LAN Controller wIPS Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected" );
	script_tag( name: "summary", value: "A vulnerability in the Cisco Adaptive Wireless Intrusion Prevention
System (wIPS) implementation in the Cisco Wireless LAN Controller (WLC) could allow an unauthenticated,
adjacent attacker to cause a denial of service (DoS) condition because the wIPS process on the WLC unexpectedly
restarts." );
	script_tag( name: "insight", value: "The vulnerability is due to lack of proper input validation of wIPS
protocol packets. An attacker could exploit this vulnerability by sending a malformed wIPS packet to the
affected device." );
	script_tag( name: "impact", value: "An exploit could allow the attacker to cause a DoS condition when the
wIPS process on the WLC unexpectedly restarts." );
	script_tag( name: "affected", value: "All versions of Cisco Wireless LAN Controller prior to the first
fixed versions of 8.0.140.0, 8.2.121.0, and 8.3.102.0." );
	script_tag( name: "solution", value: "Cisco has released software updates that address this vulnerability." );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160831-wlc-2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "8.0.140" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.140" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\.[12]" )){
	if(version_is_less( version: version, test_version: "8.2.121.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.2.121.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.3" )){
	if(version_is_less( version: version, test_version: "8.3.102.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.3.102.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

