if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112279" );
	script_version( "2021-05-21T08:11:46+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-09 13:33:51 +0200 (Wed, 09 May 2018)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-05 21:26:00 +0000 (Mon, 05 Feb 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-1044" );
	script_bugtraq_id( 102754 );
	script_name( "Moodle 3.x Privilege Escalation Vulnerability - Jan'18 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "moodle/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Privilege escalation in quiz web services." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Quiz web services allow students to see quiz results when it is prohibited in the settings. This web service is used by the mobile app." );
	script_tag( name: "affected", value: "Moodle versions 3.4, 3.3 to 3.3.3, 3.2 to 3.2.6 and 3.1 to 3.1.9" );
	script_tag( name: "solution", value: "Update to version 3.4.1, 3.3.4, 3.2.7 or 3.1.10 respectively." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=364383" );
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
if(version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.10", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.7", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.4", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "3.4.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.1", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

