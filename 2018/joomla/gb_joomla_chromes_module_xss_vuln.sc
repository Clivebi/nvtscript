CPE = "cpe:/a:joomla:joomla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812682" );
	script_version( "2021-09-29T12:07:39+0000" );
	script_cve_id( "CVE-2018-6380" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-29 12:07:39 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-13 18:09:00 +0000 (Tue, 13 Feb 2018)" );
	script_tag( name: "creation_date", value: "2018-01-31 12:52:03 +0530 (Wed, 31 Jan 2018)" );
	script_name( "Joomla 'Chromes' module XSS Vulnerability" );
	script_tag( name: "summary", value: "Joomla is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to lack of escaping in the module chromes in module
system." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow remote attackers to execute
arbitrary javascript code in the context of current user." );
	script_tag( name: "affected", value: "Joomla version 3.0.0 through 3.8.3" );
	script_tag( name: "solution", value: "Update to version 3.8.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://developer.joomla.org/security-centre/718-20180101-core-xss-vulnerability.html" );
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
if(IsMatchRegexp( vers, "^3\\." )){
	if(version_in_range( version: vers, test_version: "3.0.0", test_version2: "3.8.3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.8.4", install_path: path );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

