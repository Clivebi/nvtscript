CPE = "cpe:/a:phpbb:phpbb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108702" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:58:35 +0000 (Thu, 09 Jan 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-23 15:27:00 +0000 (Thu, 23 Jan 2020)" );
	script_cve_id( "CVE-2020-5501", "CVE-2020-5502" );
	script_name( "phpBB < 3.2.9 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "phpbb_detect.sc" );
	script_mandatory_keys( "phpBB/installed" );
	script_tag( name: "summary", value: "phpBB is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Previous versions of phpBB did not properly enforce form tokens on changing group
  avatars and handling pending group memberships." );
	script_tag( name: "impact", value: "These flaws could have been used to trick users into carrying out unwanted actions." );
	script_tag( name: "affected", value: "phpBB version before 3.2.9." );
	script_tag( name: "solution", value: "Update to version 3.2.9 or later." );
	script_xref( name: "URL", value: "https://www.phpbb.com/community/viewtopic.php?f=14&t=2534536" );
	script_xref( name: "URL", value: "https://tracker.phpbb.com/issues/?filter=15193" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "3.2.9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.2.9", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

