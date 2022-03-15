CPE = "cpe:/a:ui:unifi_protect";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146606" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-01 11:22:12 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 00:23:00 +0000 (Thu, 09 Sep 2021)" );
	script_cve_id( "CVE-2021-22943", "CVE-2021-22944" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "UniFi Protect < 1.19.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ui_unifi_protect_ubnt_detect.sc" );
	script_mandatory_keys( "ui/unifi_protect/detected" );
	script_tag( name: "summary", value: "UniFi Protect is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-22943: A malicious actor who has already gained access to a network may subsequently
  control the Protect camera(s) assigned to said network.

  - CVE-2021-22944: A malicious actor with a view-only role and network access may gain the same
  privileges as the owner of the UniFi Protect application." );
	script_tag( name: "affected", value: "UniFi Protect version 1.18.1 and prior." );
	script_tag( name: "solution", value: "Update to version 1.19.0 or later." );
	script_xref( name: "URL", value: "https://community.ui.com/releases/Security-Advisory-Bulletin-019-019/90a00abe-d6b6-43c6-92d4-0a0342f1506f" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less_equal( version: version, test_version: "1.18.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.19.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

