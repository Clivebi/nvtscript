CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108505" );
	script_version( "2021-06-02T11:05:57+0000" );
	script_cve_id( "CVE-2018-19935" );
	script_bugtraq_id( 106143 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-02 11:05:57 +0000 (Wed, 02 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-18 18:15:00 +0000 (Tue, 18 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-12-10 15:59:23 +0100 (Mon, 10 Dec 2018)" );
	script_name( "PHP 'CVE-2018-19935' - 'imap_mail' Denial of Service Vulnerability (Linux)" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=77020" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/106143" );
	script_tag( name: "summary", value: "PHP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a NULL pointer dereference and application crash
  via an empty string in the message argument to the imap_mail function of ext/imap/php_imap.c." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause a denial of service of the affected application." );
	script_tag( name: "affected", value: "PHP versions 5.x before 5.6.39, 7.0.x before 7.0.33, 7.1.x before 7.1.26
  and 7.2.x before 7.2.14." );
	script_tag( name: "solution", value: "Update to version 5.6.39, 7.0.33, 7.1.26, 7.2.14, 7.3.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
vers = infos["version"];
path = infos["location"];
if( version_in_range( version: vers, test_version: "5.0.0", test_version2: "5.6.38" ) ){
	fix = "5.6.39";
}
else {
	if( version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.32" ) ){
		fix = "7.0.33";
	}
	else {
		if( version_in_range( version: vers, test_version: "7.1.0", test_version2: "7.1.25" ) ){
			fix = "7.1.26";
		}
		else {
			if(version_in_range( version: vers, test_version: "7.2.0", test_version2: "7.2.13" )){
				fix = "7.2.14";
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

