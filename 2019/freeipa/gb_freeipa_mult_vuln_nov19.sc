CPE = "cpe:/a:freeipa:freeipa";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143217" );
	script_version( "2021-09-08T10:01:41+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 10:01:41 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-12-04 04:27:48 +0000 (Wed, 04 Dec 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-05 00:15:00 +0000 (Wed, 05 Feb 2020)" );
	script_cve_id( "CVE-2019-10195", "CVE-2019-14867" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "FreeIPA Multiple Vulnerabilities - Nov19" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_freeipa_detect.sc" );
	script_mandatory_keys( "freeipa/detected" );
	script_tag( name: "summary", value: "FreeIPA is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "FreeIPA is prone to multiple vulnerabilities:

  - Information disclosure vulnerability (CVE-2019-1019)

  - Denial of service and possible remote code execution vulnerability (CVE-2019-14867)" );
	script_tag( name: "affected", value: "FreeIPA version 4.6.x, 4.7.x and 4.8.x." );
	script_tag( name: "solution", value: "Update to version 4.6.7, 4.7.4, 4.8.3 or later." );
	script_xref( name: "URL", value: "https://www.freeipa.org/page/Releases/4.6.7" );
	script_xref( name: "URL", value: "https://www.freeipa.org/page/Releases/4.7.4" );
	script_xref( name: "URL", value: "https://www.freeipa.org/page/Releases/4.8.3" );
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
if(version_in_range( version: version, test_version: "4.6", test_version2: "4.6.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.6.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.7", test_version2: "4.7.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.7.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.8", test_version2: "4.8.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

