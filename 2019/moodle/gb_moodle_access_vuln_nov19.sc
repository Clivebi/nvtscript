CPE = "cpe:/a:moodle:moodle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143154" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-11-20 09:25:29 +0000 (Wed, 20 Nov 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:45:00 +0000 (Fri, 09 Oct 2020)" );
	script_cve_id( "CVE-2019-14883" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Moodle 3.6.x < 3.6.7, 3.7.x < 3.7.3 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to a vulnerability where email media URLs were not checked
  for the user status." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Moodle versions 3.6.x prior 3.6.7 and 3.7.x prior to 3.7.3." );
	script_tag( name: "solution", value: "Update to version 3.6.7, 3.7.3 or later." );
	script_xref( name: "URL", value: "https://moodle.org/security/" );
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
if(version_in_range( version: version, test_version: "3.6", test_version2: "3.6.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.7", test_version2: "3.7.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7.3", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

