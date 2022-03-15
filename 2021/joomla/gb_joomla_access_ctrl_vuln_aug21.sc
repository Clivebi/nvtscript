CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146550" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-25 06:51:48 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 02:11:00 +0000 (Tue, 31 Aug 2021)" );
	script_cve_id( "CVE-2021-26040" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla! 4.0.0 Access Control Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "Joomla! is prone to an access control vulnerability in the
  com_media deletion endpoint." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The media manager does not correctly check the user's
  permissions before executing a file deletion command." );
	script_tag( name: "affected", value: "Joomla! version 4.0.0." );
	script_tag( name: "solution", value: "Update to version 4.0.1 or later." );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/861-20210801-core-insufficient-access-control-for-com-media-deletion-endpoint" );
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
if(version_is_equal( version: version, test_version: "4.0.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.1", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

