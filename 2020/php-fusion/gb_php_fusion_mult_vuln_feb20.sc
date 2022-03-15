CPE = "cpe:/a:php-fusion:php-fusion";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108851" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-14 12:41:58 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-13 17:13:00 +0000 (Thu, 13 Aug 2020)" );
	script_cve_id( "CVE-2020-17449", "CVE-2020-17450" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP-Fusion < 9.03.30 Multiple XSS Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_mandatory_keys( "php-fusion/detected" );
	script_tag( name: "summary", value: "PHP-Fusion is prone to multiple cross-site scripting (XSS) vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PHP-Fusion is prone to multiple vulnerabilities:

  - Stored XSS vulnerability in the Edit Blog Post Function (CVE-2020-17449)

  - Reflected XSS vulnerability in the Preview Blog Post Function (CVE-2020-17450)" );
	script_tag( name: "affected", value: "PHP-Fusion versions prior to 9.03.30." );
	script_tag( name: "solution", value: "Update to version 9.03.30 or later." );
	script_xref( name: "URL", value: "https://sec-consult.com/en/blog/advisories/multiple-cross-site-scripting-xss-vulnerabilities-in-php-fusion-cms/" );
	script_xref( name: "URL", value: "https://www.php-fusion.co.uk/infusions/news/news.php?readmore=638" );
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
if(version_is_less( version: version, test_version: "9.03.30" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.03.30", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

