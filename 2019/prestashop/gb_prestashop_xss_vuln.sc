CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142486" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-06-04 07:36:57 +0000 (Tue, 04 Jun 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-28 14:59:00 +0000 (Tue, 28 May 2019)" );
	script_cve_id( "CVE-2019-11876" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop <= 1.7.5.2 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The shop_country parameter in the install/index.php installation
  script/component is affected by Reflected XSS. Exploitation by a malicious actor requires the user to follow the
  initial stages of the setup (accepting terms and conditions) before executing the malicious link." );
	script_tag( name: "affected", value: "PrestaShop version 1.7.5.2 and probably prior." );
	script_tag( name: "solution", value: "Update to version 1.7.6 or later." );
	script_xref( name: "URL", value: "https://www.logicallysecure.com/blog/xss-presta-xss-drupal/" );
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
path = infos["location"];
if(version_is_less_equal( version: version, test_version: "1.7.5.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

