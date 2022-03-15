CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146384" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-27 02:56:29 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-04 19:06:00 +0000 (Wed, 04 Aug 2021)" );
	script_cve_id( "CVE-2021-21440", "CVE-2021-36092" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS Multiple Vulnerabilities (OSA-2021-11, OSA-2021-15)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-21440: Support Bundle includes S/Mime and PGP keys

  - CVE-2021-36092: XSS attack using special link in email" );
	script_tag( name: "affected", value: "OTRS version 6.x, 7.0.x through 7.0.27 and 8.0.x through 8.0.14." );
	script_tag( name: "solution", value: "Update to version 7.0.28, 8.0.15 or later." );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2021-10/" );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2021-15/" );
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
if(version_in_range( version: version, test_version: "6.0", test_version2: "7.0.27" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.28", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0", test_version2: "8.0.14" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.15", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

