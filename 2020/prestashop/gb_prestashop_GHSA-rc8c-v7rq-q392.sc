CPE = "cpe:/a:prestashop:prestashop";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144677" );
	script_version( "2021-07-07T11:00:41+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-09-29 06:40:44 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-30 14:18:00 +0000 (Wed, 30 Sep 2020)" );
	script_cve_id( "CVE-2020-15162" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PrestaShop 1.5.0.0 < 1.7.6.8 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_prestashop_detect.sc" );
	script_mandatory_keys( "prestashop/detected" );
	script_tag( name: "summary", value: "PrestaShop is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Users are allowed to send compromised files, these attachments allow people to
  input malicious JavaScript which triggered XSS payload." );
	script_tag( name: "affected", value: "PrestaShop versions 1.5.0.0 - 1.7.6.7." );
	script_tag( name: "solution", value: "Update to version 1.7.6.8 or later." );
	script_xref( name: "URL", value: "https://github.com/PrestaShop/PrestaShop/security/advisories/GHSA-rc8c-v7rq-q392" );
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
if(version_in_range( version: version, test_version: "1.5.0.0", test_version2: "1.7.6.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.7.6.8", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

