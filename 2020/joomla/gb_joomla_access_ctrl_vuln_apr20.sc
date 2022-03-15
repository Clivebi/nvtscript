CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143745" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-04-22 03:06:53 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-29 18:01:00 +0000 (Wed, 29 Apr 2020)" );
	script_cve_id( "CVE-2020-11891" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla! 3.8.8 - 3.9.16 Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "Joomla! is prone to an access control vulnerability in com_users access level
  editing function." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Incorrect ACL checks in the access level section of com_users allow the
  unauthorized editing of usergroups." );
	script_tag( name: "affected", value: "Joomla! versions 3.8.8 - 3.9.16." );
	script_tag( name: "solution", value: "Update to version 3.9.17 or later." );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/809-20200401-core-incorrect-access-control-in-com-users-access-level-editing-function.html" );
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
if(version_in_range( version: version, test_version: "3.8.8", test_version2: "3.9.16" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.17", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

