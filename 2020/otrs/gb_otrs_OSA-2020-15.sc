CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144741" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-20 05:18:52 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-21 14:31:00 +0000 (Wed, 21 Oct 2020)" );
	script_cve_id( "CVE-2020-1777" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS 7.0.x < 7.0.22, 8.0.x < 8.0.7 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Agent names that participates in a chat conversation are revealed in certain
  parts of the external interface as well as in chat transcriptions inside the tickets, when system is configured
  to mask real agent names." );
	script_tag( name: "affected", value: "OTRS 7.0.x - 7.0.21 and 8.0.x - 8.0.6." );
	script_tag( name: "solution", value: "Update to version 7.0.22, 8.0.7 or later." );
	script_xref( name: "URL", value: "https://otrs.com/release-notes/otrs-security-advisory-2020-15/" );
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
if(version_in_range( version: version, test_version: "7.0.0", test_version2: "7.0.21" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.22", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0", test_version2: "8.0.6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.0.7", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

