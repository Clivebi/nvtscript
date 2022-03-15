CPE = "cpe:/o:cisco:wireless_lan_controller_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140472" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-02 09:51:43 +0700 (Thu, 02 Nov 2017)" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:22:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2017-12281" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cisco Aironet Access Points MAC Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_wlc_consolidation.sc" );
	script_mandatory_keys( "cisco/wlc/detected", "cisco/wlc/model" );
	script_tag( name: "summary", value: "A vulnerability in the implementation of Protected Extensible Authentication
Protocol (PEAP) functionality for standalone configurations of Cisco Aironet 1800, 2800, and 3800 Series Access
Points could allow an unauthenticated, adjacent attacker to bypass authentication and connect to an affected
device." );
	script_tag( name: "insight", value: "The vulnerability exists because the affected device uses an incorrect
default configuration setting of fail open when running in standalone mode. An attacker could exploit this
vulnerability by attempting to connect to an affected device." );
	script_tag( name: "impact", value: "A successful exploit could allow the attacker to bypass authentication and connect to the affected device." );
	script_tag( name: "solution", value: "See the referenced advisory for a solution." );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171101-aironet3" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
model = get_kb_item( "cisco/wlc/model" );
if(!model || ( ( !IsMatchRegexp( model, "^AIR-AP156[0-9]" ) ) && ( !IsMatchRegexp( model, "^AIR-AP(28|38)[0-9]{2}" ) ) )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^8\\.2\\." )){
	if(version_is_less( version: version, test_version: "8.2.160.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.2.160.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.3\\." )){
	if(version_is_less( version: version, test_version: "8.3.121.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.3.121.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.4\\." )){
	if(version_is_less( version: version, test_version: "8.4.100.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.4.100.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^8\\.5\\." )){
	if(version_is_less( version: version, test_version: "8.5.103.0" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "8.5.103.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

