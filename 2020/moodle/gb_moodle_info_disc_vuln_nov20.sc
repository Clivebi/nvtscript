if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112847" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-11-27 12:46:11 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-01 17:53:00 +0000 (Tue, 01 Dec 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-25703" );
	script_name( "Moodle 3.7.x < 3.7.9, 3.8.x < 3.8.6, 3.9.x < 3.9.3 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The participants table download always includes user emails,
  but should only do so when users' emails are not hidden." );
	script_tag( name: "impact", value: "Successful exploitation would allow an authenticated attacker to
  disclose user emails." );
	script_tag( name: "affected", value: "Moodle versions 3.7.0 through 3.7.8,
  3.8.0 through 3.8.5 and 3.9.0 through 3.9.2." );
	script_tag( name: "solution", value: "Update to version 3.7.9, 3.8.6, 3.9.3 or 3.10 respectively." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=413941" );
	exit( 0 );
}
CPE = "cpe:/a:moodle:moodle";
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
if(version_in_range( version: version, test_version: "3.7.0", test_version2: "3.7.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.7.9", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.8.0", test_version2: "3.8.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.8.6", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.9.0", test_version2: "3.9.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.3", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

