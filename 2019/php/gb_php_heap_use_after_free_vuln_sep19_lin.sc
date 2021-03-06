CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108635" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-09-09 08:48:28 +0000 (Mon, 09 Sep 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP Heap Use-After-Free Vulnerability - Sep19 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PHP is prone to a heap-based use-after-free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "PHP is prone to a heap use-after-free in pcrelib (cmb)." );
	script_tag( name: "affected", value: "PHP versions before 7.1.32." );
	script_tag( name: "solution", value: "Update to version 7.1.32 or later." );
	script_xref( name: "URL", value: "http://bugs.php.net/75457" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.1.32" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less( version: version, test_version: "7.1.32" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.32", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

