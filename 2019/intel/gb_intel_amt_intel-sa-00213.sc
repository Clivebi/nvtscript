CPE = "cpe:/h:intel:active_management_technology";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142466" );
	script_version( "2021-09-06T11:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 11:01:35 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-05-27 07:20:26 +0000 (Mon, 27 May 2019)" );
	script_tag( name: "cvss_base", value: "5.2" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-20 16:15:00 +0000 (Thu, 20 Jun 2019)" );
	script_cve_id( "CVE-2019-0092", "CVE-2019-0094", "CVE-2019-0096", "CVE-2019-0097" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00213)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_intel_amt_webui_detect.sc" );
	script_mandatory_keys( "intel_amt/installed" );
	script_tag( name: "summary", value: "Multiple potential security vulnerabilities in Intel Active Management
  Technology (Intel AMT) may allow escalation of privilege, information disclosure, and/or denial of service." );
	script_tag( name: "insight", value: "Intel Active Management Technology is prone to multiple vulnerabilities:

  - Insufficient input validation vulnerability in subsystem may allow an unauthenticated user to potentially
    enable escalation of privilege via physical access. (CVE-2019-0092)

  - Insufficient input validation vulnerability in subsystem may allow an unauthenticated user to potentially
    enable denial of service via adjacent network access. (CVE-2019-0094)

  - Out of bound write vulnerability in subsystem may allow an authenticated user to potentially enable escalation
    of privilege via adjacent network access. (CVE-2019-0096)

  - Insufficient input validation vulnerability in subsystem may allow a privileged user to potentially enable
    denial of service via network access. (CVE-2019-0097)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Intel Active Management Technology 11.0 to 11.8.60, 11.10 to 11.11.60,
  11.20 to 11.22.60 and 12.0 to 12.0.20." );
	script_tag( name: "solution", value: "Upgrade to version 11.8.65, 11.11.65, 11.22.65, 12.0.35 or later." );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00213.html" );
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
path = infos["location"];
if(version_in_range( version: version, test_version: "11.0", test_version2: "11.8.60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.8.65", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.10", test_version2: "11.11.60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.11.65", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "11.20", test_version2: "11.22.60" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "11.22.65", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "12.0", test_version2: "12.0.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "12.0.35", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

