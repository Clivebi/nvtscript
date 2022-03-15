CPE = "cpe:/a:pi-hole:web";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146441" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-05 08:52:37 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-12 15:19:00 +0000 (Thu, 12 Aug 2021)" );
	script_cve_id( "CVE-2021-32706", "CVE-2021-32793" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Pi-hole Ad-Blocker Web (AdminLTE) < 5.5.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pi-hole_detect.sc" );
	script_mandatory_keys( "pi-hole/detected" );
	script_tag( name: "summary", value: "Pi-hole Ad-Blocker Web (AdminLTE) is prone to multiple
  vulnerabilities." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - CVE-2021-32706: Authenticated remote code execution (RCE)

  - CVE-2021-32793: Stored cross-site scripting (XSS)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Pi-hole Ad-Blocker Web (AdminLTE) version 5.5 and prior." );
	script_tag( name: "solution", value: "Update to version 5.5.1 or later." );
	script_xref( name: "URL", value: "https://github.com/pi-hole/AdminLTE/security/advisories/GHSA-5cm9-6p3m-v259" );
	script_xref( name: "URL", value: "https://github.com/pi-hole/AdminLTE/security/advisories/GHSA-g3w6-q4fg-p8x8" );
	script_xref( name: "URL", value: "https://github.com/pi-hole/AdminLTE/releases/tag/v5.5.1" );
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
if(version_is_less( version: version, test_version: "5.5.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.5.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

