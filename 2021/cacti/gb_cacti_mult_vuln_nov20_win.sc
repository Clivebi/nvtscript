if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112854" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-14 11:57:11 +0000 (Thu, 14 Jan 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-21 16:51:00 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-35701" );
	script_name( "Cacti 1.2.x < 1.2.17 Multiple Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "cacti/installed", "Host/runs_windows" );
	script_tag( name: "summary", value: "Cacti is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - A vulnerability in data_debug.php allows remote authenticated
  attackers to execute arbitrary SQL commands via the site_id parameter

  - Multiple stored cross-site scripting vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker
  to execute arbitrary SQL commands or JavaScript code." );
	script_tag( name: "affected", value: "Cacti 1.2.x through 1.2.16." );
	script_tag( name: "solution", value: "Update Cacti to version 1.2.17 or later." );
	script_xref( name: "URL", value: "https://asaf.me/2020/12/15/cacti-1-2-0-to-1-2-16-sql-injection/" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/4022" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/4019" );
	script_xref( name: "URL", value: "https://github.com/Cacti/cacti/issues/4035" );
	exit( 0 );
}
CPE = "cpe:/a:cacti:cacti";
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
if(version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.17", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

