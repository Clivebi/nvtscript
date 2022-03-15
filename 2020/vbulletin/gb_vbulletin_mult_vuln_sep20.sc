CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144712" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-07 08:55:56 +0000 (Wed, 07 Oct 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-04 01:32:00 +0000 (Fri, 04 Sep 2020)" );
	script_cve_id( "CVE-2020-25115", "CVE-2020-25116", "CVE-2020-25117", "CVE-2020-25118", "CVE-2020-25119", "CVE-2020-25120", "CVE-2020-25121", "CVE-2020-25122", "CVE-2020-25123", "CVE-2020-25124" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "vBulletin <= 5.6.3 Multiple XSS Vulnerabilities" );
	script_tag( name: "solution_type", value: "NoneAvailable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_tag( name: "summary", value: "vBulletin is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "vBulletin version 5.6.3 and probably prior." );
	script_tag( name: "solution", value: "No known solution is available as of 19th May, 2021.
  Information regarding this issue will be updated once solution details are available." );
	script_xref( name: "URL", value: "https://pentest-vincent.blogspot.com/2020/09/vbulletin-563-multiple-persistent-cross.html" );
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
if(version_is_less_equal( version: version, test_version: "5.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

