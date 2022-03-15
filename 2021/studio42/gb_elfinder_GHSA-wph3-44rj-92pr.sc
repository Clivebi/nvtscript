CPE = "cpe:/a:studio42:elfinder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146121" );
	script_version( "2021-08-26T14:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-15 03:04:45 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-29 16:29:00 +0000 (Tue, 29 Jun 2021)" );
	script_cve_id( "CVE-2021-32682" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "elFinder < 2.1.59 Multiple Vulnerabilities (GHSA-wph3-44rj-92pr)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elfinder_detect.sc" );
	script_mandatory_keys( "studio42/elfinder/detected" );
	script_tag( name: "summary", value: "elFinder is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "These vulnerabilities can allow an attacker to execute arbitrary
  code and commands on the server hosting the elFinder PHP connector, even with the minimal
  configuration." );
	script_tag( name: "affected", value: "elFinder version 2.1.58 and prior." );
	script_tag( name: "solution", value: "Update to version 2.1.59 or later." );
	script_xref( name: "URL", value: "https://github.com/Studio-42/elFinder/security/advisories/GHSA-wph3-44rj-92pr" );
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
if(version_is_less( version: version, test_version: "2.1.59" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.59", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

