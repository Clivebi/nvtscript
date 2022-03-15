if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113180" );
	script_version( "2021-05-21T08:11:46+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-05-08 14:24:34 +0200 (Tue, 08 May 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-2644", "CVE-2017-2645" );
	script_bugtraq_id( 96979, 96982 );
	script_name( "Moodle 3.x Multiple XSS Vulnerabilities - Mar'17 (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_moodle_cms_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "moodle/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "Moodle is prone to multiple XSS vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on a target host." );
	script_tag( name: "insight", value: "Users have the ability to upload evidence of prior learning.
  In this, both in the text and in the attachment, an XSS script could be embedded." );
	script_tag( name: "affected", value: "Moodle versions 3.1.0 through 3.1.4 and 3.2.0 through 3.2.1." );
	script_tag( name: "solution", value: "Update to version 3.1.5 or 3.2.2 respectively." );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=349421" );
	script_xref( name: "URL", value: "https://moodle.org/mod/forum/discuss.php?d=349422" );
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
if(version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

