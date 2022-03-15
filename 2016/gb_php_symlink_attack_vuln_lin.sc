CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809736" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2014-3981" );
	script_bugtraq_id( 67837 );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-12-01 18:38:59 +0530 (Thu, 01 Dec 2016)" );
	script_name( "PHP Symlink Attack Vulnerability (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to a symlink attack vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to insecure temporary file
  use in the configure script." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows local
  users to overwrite arbitrary files via a symlink attack on the
  '/tmp/phpglibccheck' file." );
	script_tag( name: "affected", value: "PHP versions 5.5.x before 5.5.14, 5.4.x
  before 5.4.30, 5.3.x before 5.3.29 on Linux" );
	script_tag( name: "solution", value: "Update to PHP version 5.5.14 or 5.4.30
  or 5.3.29 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "https://bugs.php.net/bug.php?id=67390" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2014/Jun/21" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^5\\." )){
	if( version_in_range( version: vers, test_version: "5.3", test_version2: "5.3.28" ) ){
		VULN = TRUE;
		fix = "5.3.29";
	}
	else {
		if( version_in_range( version: vers, test_version: "5.4", test_version2: "5.4.29" ) ){
			VULN = TRUE;
			fix = "5.4.30";
		}
		else {
			if(version_in_range( version: vers, test_version: "5.5", test_version2: "5.5.13" )){
				VULN = TRUE;
				fix = "5.5.14";
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: vers, fixed_version: fix );
		security_message( data: report, port: port );
		exit( 0 );
	}
}
exit( 99 );

