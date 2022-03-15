CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144497" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-28 03:00:13 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-28 16:22:00 +0000 (Fri, 28 Aug 2020)" );
	script_cve_id( "CVE-2020-24598" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Joomla! 3.0.0 - 3.9.20 Open Redirect Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "joomla_detect.sc" );
	script_mandatory_keys( "joomla/installed" );
	script_tag( name: "summary", value: "Joomla! is prone to an open redirect vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Lack of input validation in com_content leads to an open redirect." );
	script_tag( name: "affected", value: "Joomla! versions 3.0.0 - 3.9.20." );
	script_tag( name: "solution", value: "Update to version 3.9.21 or later." );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/825-20200802-core-open-redirect-in-com-content-vote-feature" );
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
if(version_in_range( version: version, test_version: "3.0.0", test_version2: "3.9.20" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.9.21", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

