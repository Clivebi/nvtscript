CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143163" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-11-22 03:15:57 +0000 (Fri, 22 Nov 2019)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-04 14:46:00 +0000 (Wed, 04 Dec 2019)" );
	script_cve_id( "CVE-2019-18790", "CVE-2019-18610" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk Multiple Vulnerabilities (AST-2019-006, AST-2019-007)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Asterisk is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Asterisk is prone to multiple vulnerabilities:

  - AMI user could execute system commands (CVE-2019-18610)

  - SIP request can change address of a SIP peer (CVE-2019-18790)" );
	script_tag( name: "affected", value: "Asterisk Open Source 13.x, 16.x, 17.x and 13.21 Certified Asterisk." );
	script_tag( name: "solution", value: "Upgrade to Version 13.29.2, 16.6.2, 17.0.1, 13.21-cert5 or later." );
	script_xref( name: "URL", value: "https://downloads.asterisk.org/pub/security/AST-2019-006.html" );
	script_xref( name: "URL", value: "https://downloads.asterisk.org/pub/security/AST-2019-007.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( version, "^13\\." )){
	if( IsMatchRegexp( version, "^13\\.21cert" ) ){
		if(revcomp( a: version, b: "13.21cert5" ) < 0){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.21-cert5" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
	else {
		if(version_is_less( version: version, test_version: "13.29.2" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.29.2" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^16\\." )){
	if(version_is_less( version: version, test_version: "16.6.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.6.2" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^17\\." )){
	if(version_is_less( version: version, test_version: "17.0.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "17.0.1" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

