CPE = "cpe:/a:moodle:moodle";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146224" );
	script_version( "2021-07-06T04:35:09+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 04:35:09 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-06 04:27:36 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_cve_id( "CVE-2021-32477" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Moodle 3.10.x < 3.10.4 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_mandatory_keys( "moodle/detected" );
	script_tag( name: "summary", value: "Moodle is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The last time a user accessed the mobile app is displayed on
  their profile page, but should be restricted to users with the relevant capability (site
  administrators by default)." );
	script_tag( name: "affected", value: "Moodle version 3.10 through 3.10.3." );
	script_tag( name: "solution", value: "Update to version 3.10.4 or later." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=422313" );
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
if(version_in_range( version: version, test_version: "3.10.0", test_version2: "3.10.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.10.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

