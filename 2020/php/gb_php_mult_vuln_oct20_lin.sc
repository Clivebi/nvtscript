CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144694" );
	script_version( "2021-07-08T11:00:45+0000" );
	script_tag( name: "last_modification", value: "2021-07-08 11:00:45 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-10-02 04:18:31 +0000 (Fri, 02 Oct 2020)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_cve_id( "CVE-2020-7069", "CVE-2020-7070" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PHP < 7.2.34, 7.3 < 7.3.23, 7.4 < 7.4.11 Multiple Vulnerabilities - October20 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - Wrong ciphertext/tag in AES-CCM encryption for a 12 bytes IV (CVE-2020-7069)

  - PHP parses encoded cookie names so malicious '__Host-' cookies can be sent (CVE-2020-7070)" );
	script_tag( name: "affected", value: "PHP versions prior 7.2.34, 7.3 prior 7.3.23 and 7.4 prior to 7.4.11." );
	script_tag( name: "solution", value: "Update to version 7.2.34, 7.3.23, 7.4.11 or later." );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.2.34" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.3.23" );
	script_xref( name: "URL", value: "https://www.php.net/ChangeLog-7.php#7.4.11" );
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
location = infos["location"];
if(version_is_less( version: version, test_version: "7.2.34" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.2.34", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.3.0", test_version2: "7.3.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.3.23", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.4.0", test_version2: "7.4.10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.4.11", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

