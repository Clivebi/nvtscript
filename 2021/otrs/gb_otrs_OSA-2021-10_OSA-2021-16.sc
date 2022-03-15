CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146648" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-07 07:28:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-09 21:41:00 +0000 (Thu, 09 Sep 2021)" );
	script_cve_id( "CVE-2021-36093", "CVE-2021-36096", "CVE-2021-21440" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS Multiple Vulnerabilities (OSA-2021-10, OSA-2021-16)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-36093: DoS attack using PostMaster filters

  - CVE-2021-36096, CVE-2021-21440: Support Bundle includes S/Mime and PGP keys and secrets" );
	script_tag( name: "affected", value: "OTRS version 6.x, 7.0.x through 7.0.28 and 8.0.x through 8.0.15." );
	script_tag( name: "solution", value: "Update to version 7.0.29, 8.0.16 or later." );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2021-10/" );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2021-16/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "6.0.1", test_version2: "7.0.28" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.29", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.15" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.16", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

