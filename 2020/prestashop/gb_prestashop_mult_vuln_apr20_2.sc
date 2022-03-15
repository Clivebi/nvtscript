CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144415" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-19 04:52:28 +0000 (Wed, 19 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-23 19:10:00 +0000 (Thu, 23 Apr 2020)" );
	script_cve_id( "CVE-2020-5265", "CVE-2020-5269" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop 1.7.6.1 < 1.7.6.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to multiple cross-site scripting vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vunerabilities exist:

  - Reflected XSS on AdminAttributesGroups page (CVE-2020-5265)

  - Reflected XSS on AdminFeatures page (CVE-2020-5269)" );
	script_tag( name: "affected", value: "PrestaShop versions 1.7.6.1 - 1.7.6.4." );
	script_tag( name: "solution", value: "Update to version 1.7.6.5 or later." );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-7fmr-5vcc-329j" );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-87jh-7xpg-6v93" );
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
if(version_in_range( version: version, test_version: "1.7.6.1", test_version2: "1.7.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

