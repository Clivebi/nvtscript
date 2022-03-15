CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813900" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2017-9118" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)" );
	script_tag( name: "creation_date", value: "2018-08-06 18:35:25 +0530 (Mon, 06 Aug 2018)" );
	script_name( "PHP 'php_pcre_replace_impl' Out of Bounds Access Vulnerability (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to an out of bounds access vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  'php_pcre_replace_impl()' in '/sapi/cli/php' which improperly handles 'preg_replace' calls." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain out of bounds access." );
	script_tag( name: "affected", value: "PHP version 7.1.5 on Linux." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=74604" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_equal( version: version, test_version: "7.1.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

