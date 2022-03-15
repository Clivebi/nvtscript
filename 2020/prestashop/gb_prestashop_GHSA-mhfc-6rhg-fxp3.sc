CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143586" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-03-10 04:49:47 +0000 (Tue, 10 Mar 2020)" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-05 23:38:00 +0000 (Thu, 05 Mar 2020)" );
	script_cve_id( "CVE-2020-5250" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop < 1.7.6.4 Information Stealing Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to an information stealing vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "When a customer edits their address, they can freely change the id_address in
  the form, and thus steal someone else's address. It's the same with CustomerForm, you're able to change the
  id_customer and change all information of all accounts." );
	script_tag( name: "affected", value: "PrestaShop versions 1.7.x prior to version 1.7.6.4." );
	script_tag( name: "solution", value: "Update to version 1.7.6.4 or later." );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-mhfc-6rhg-fxp3" );
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
if(version_in_range( version: version, test_version: "1.7.0.0", test_version2: "1.7.6.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

