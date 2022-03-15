if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112372" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-15881" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-30 10:12:03 +0200 (Thu, 30 Aug 2018)" );
	script_name( "Joomla < 3.8.12 ACL Violation Vulnerability" );
	script_tag( name: "summary", value: "Joomla is prone to an ACL violation vulnerability in custom fields." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Inadequate checks regarding disabled fields can lead to an ACL violation." );
	script_tag( name: "affected", value: "Joomla versions 3.7.0 through 3.8.11." );
	script_tag( name: "solution", value: "Update to version 3.8.12 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/745-20180803-core-acl-violation-in-custom-fields.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:joomla:joomla";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "3.7.0", test_version2: "3.8.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.8.12", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

