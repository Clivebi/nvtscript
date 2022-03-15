CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144414" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-19 04:26:59 +0000 (Wed, 19 Aug 2020)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-27 17:52:00 +0000 (Mon, 27 Apr 2020)" );
	script_cve_id( "CVE-2020-5264", "CVE-2020-5288", "CVE-2020-5293" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop 1.7.0.0 < 1.7.6.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vunerabilities exist:

  - Reflected XSS in security compromised page (CVE-2020-5264)

  - Improper access control on product attributes page (CVE-2020-5288)

  - Improper access control on product page with combinations, attachments and specific prices (CVE-2020-5293)" );
	script_tag( name: "affected", value: "PrestaShop versions 1.7.0.0 - 1.7.6.4." );
	script_tag( name: "solution", value: "Update to version 1.7.6.5 or later." );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-48vj-vvr6-jj4f" );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-4wxg-33h3-3w5r" );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-cvjj-grfv-f56w" );
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
if(version_in_range( version: version, test_version: "1.7.0.0", test_version2: "1.7.6.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6.5", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

