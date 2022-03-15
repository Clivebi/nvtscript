CPE = "cpe:/a:phpipam:phpipam";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142936" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-25 10:09:35 +0000 (Wed, 25 Sep 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-01 23:15:00 +0000 (Tue, 01 Oct 2019)" );
	script_cve_id( "CVE-2019-16692", "CVE-2019-16693", "CVE-2019-16694", "CVE-2019-16695", "CVE-2019-16696", "CVE-2020-7988" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "phpIPAM <= 1.4 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ipam_detect.sc" );
	script_mandatory_keys( "phpipam/installed" );
	script_tag( name: "summary", value: "phpIPAM is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "phpIPAM is prone to multiple vulnerabilities:

  - Multiple SQL injection vulnerabilities (CVE-2019-16692, CVE-2019-16693, CVE-2019-16694, CVE-2019-16695,
    CVE-2019-16696)

  - CSRF vulnerability" );
	script_tag( name: "affected", value: "phpIPAM version 1.4 and prior." );
	script_tag( name: "solution", value: "Update to the latest version of phpIPAM." );
	script_xref( name: "URL", value: "https://github.com/phpipam/phpipam/issues/2738" );
	script_xref( name: "URL", value: "https://pastebin.com/ZPECbgZb" );
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
if(version_is_less_equal( version: version, test_version: "1.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Update to the latest version", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

