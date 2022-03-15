if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113748" );
	script_version( "2021-07-22T11:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 11:01:40 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-31 11:54:15 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-01 15:42:00 +0000 (Tue, 01 Sep 2020)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2020-23658" );
	script_name( "PHP-Fusion <= 9.03.60 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_fusion_detect.sc" );
	script_mandatory_keys( "php-fusion/detected" );
	script_tag( name: "summary", value: "PHP-Fusion is prone to a cross-site scripting (XSS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability exists in infusions/member_poll_panel/poll_admin.php." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to inject arbitrary HTML and JavaScript into the site." );
	script_tag( name: "affected", value: "PHP-Fusion through version 9.03.60." );
	script_tag( name: "solution", value: "Update to version 9.03.70." );
	script_xref( name: "URL", value: "https://github.com/php-fusion/PHP-Fusion/issues/2325" );
	exit( 0 );
}
CPE = "cpe:/a:php-fusion:php-fusion";
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
if(version_is_less( version: version, test_version: "9.03.70" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.03.70", install_path: location );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

