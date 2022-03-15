CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813408" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-11323", "CVE-2018-11322" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-05-23 12:35:14 +0530 (Wed, 23 May 2018)" );
	script_name( "Joomla Multiple Vulnerabilities-01 May18 (20180502/20180501)" );
	script_tag( name: "summary", value: "Joomla is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error where depending on the server configuration, PHAR files might be handled as executable PHP scripts by
the webserver.

  - Inadequate checks for access level permissions." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to modify the access levels
of user groups with higher permissions and use PHAR files as executable PHP scripts." );
	script_tag( name: "affected", value: "Joomla version 2.5.0 through 3.8.7" );
	script_tag( name: "solution", value: "Update to version 3.8.8 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/730-20180502-core-add-phar-files-to-the-upload-blacklist.html" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/729-20180501-core-acl-violation-in-access-levels.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "2.5.0", test_version2: "3.8.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.8.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

