CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805658" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2015-3330" );
	script_bugtraq_id( 74204 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-06-17 16:00:15 +0530 (Wed, 17 Jun 2015)" );
	script_name( "PHP Multiple Vulnerabilities - 04 - Jun15 (Linux)" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=69085" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2015/06/01/4" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to vulnerability in
  'php_handler' function in sapi/apache2handler/sapi_apache2.c script in PHP." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to cause a denial of service or possibly execute arbitrary
  code via pipelined HTTP requests." );
	script_tag( name: "affected", value: "PHP versions before 5.4.40, 5.5.x before
  5.5.24, and 5.6.x before 5.6.8." );
	script_tag( name: "solution", value: "Update to PHP 5.4.40 or 5.5.24 or 5.6.8
  or later." );
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
if(IsMatchRegexp( vers, "^5\\.5\\." )){
	if(version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.23" )){
		fix = "5.5.24";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( vers, "^5\\.6\\." )){
	if(version_in_range( version: vers, test_version: "5.6.0", test_version2: "5.6.7" )){
		fix = "5.6.8";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( vers, "^5\\.4\\." )){
	if(version_is_less( version: vers, test_version: "5.4.40" )){
		fix = "5.4.40";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix, install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

