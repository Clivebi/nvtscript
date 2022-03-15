if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113182" );
	script_version( "2021-05-19T13:27:56+0200" );
	script_tag( name: "last_modification", value: "2021-05-19 13:27:56 +0200 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-09 12:40:45 +0200 (Wed, 09 May 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-01 14:52:00 +0000 (Tue, 01 Dec 2020)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-7531" );
	script_bugtraq_id( 99618 );
	script_name( "Moodle 3.3.0 Information Disclosure Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "moodle/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "The course overview block reveals activities in hidden courses." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Moodle version 3.3.0." );
	script_tag( name: "solution", value: "Update to version 3.3.1." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=355555" );
	exit( 0 );
}
CPE = "cpe:/a:moodle:moodle";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( port: port, cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_equal( version: version, test_version: "3.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

