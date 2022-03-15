CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105837" );
	script_cve_id( "CVE-2016-1460" );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:N/I:N/A:C" );
	script_version( "2021-06-02T09:00:58+0000" );
	script_tag( name: "last_modification", value: "2021-06-02 09:00:58 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-07-29 18:17:42 +0200 (Fri, 29 Jul 2016)" );
	script_name( "Cisco Wireless LAN Controller Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-wlc" );
	script_tag( name: "summary", value: "A vulnerability in wireless frame management service of the Cisco Wireless LAN Controller (WLC) could allow an unauthenticated, adjacent attacker to cause a denial of service (DoS) condition on the affected device." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by sending crafted wireless management frames to the device." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "affected", value: "Cisco Wireless LAN Controller (WLC) versions 7.4(121.0) and
  8.0(0.30220.385) are affected." );
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
if(IsMatchRegexp( vers, "^7\\.4" )){
	if(version_is_less( version: vers, test_version: "7.4.140.1" )){
		fix = "7.4(140.1)";
	}
}
if(IsMatchRegexp( vers, "^8\\.0" )){
	if(version_is_less( version: vers, test_version: "8.0.100.0" )){
		fix = "8.0(100.0)";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

