CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144424" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-19 06:02:57 +0000 (Wed, 19 Aug 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-07 16:58:00 +0000 (Tue, 07 Jul 2020)" );
	script_cve_id( "CVE-2020-15080" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop 1.7.4.0 - 1.7.6.5 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to an information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Some files should not be in the release archive, and others should not be accessible." );
	script_tag( name: "affected", value: "PrestaShop versions 1.7.4.0 - 1.7.6.5." );
	script_tag( name: "solution", value: "Update to version 1.7.6.6 or later." );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-492w-2pp5-xhvg" );
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
if(version_in_range( version: version, test_version: "1.7.4.0", test_version2: "1.7.6.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6.6", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
