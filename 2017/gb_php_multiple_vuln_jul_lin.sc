CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811482" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-11145", "CVE-2017-11144", "CVE-2017-11146", "CVE-2017-11628", "CVE-2017-7890" );
	script_bugtraq_id( 99492, 99550, 99605, 99612, 99489 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)" );
	script_tag( name: "creation_date", value: "2017-07-11 19:29:21 +0530 (Tue, 11 Jul 2017)" );
	script_name( "PHP Multiple Vulnerabilities - Jul17 (Linux)" );
	script_tag( name: "summary", value: "PHP is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - An ext/date/lib/parse_date.c out-of-bounds read affecting the php_parse_date
    function.

  - The openssl extension PEM sealing code did not check the return value of the
    OpenSSL sealing function.

  - lack of bounds checks in the date extension's timelib_meridian parsing code.

  - A stack-based buffer overflow in the zend_ini_do_op() function in
   'Zend/zend_ini_parser.c' script.

  - The GIF decoding function gdImageCreateFromGifCtx in gd_gif_in.c in the GD
    Graphics Library (aka libgd) does not zero colorMap arrays before use." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allow
  remote attackers to leak information from the interpreter, crash PHP
  interpreter and also disclose sensitive information." );
	script_tag( name: "affected", value: "PHP versions before 5.6.31, 7.x before 7.0.21,
  and 7.1.x before 7.1.7" );
	script_tag( name: "solution", value: "Update to PHP version 5.6.31, 7.0.21, 7.1.7,
  or later." );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( phpport = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: phpport )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "5.6.31" )){
	fix = "5.6.31";
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.20" )){
	fix = "7.0.21";
}
if(IsMatchRegexp( vers, "^7\\.1" ) && version_is_less( version: vers, test_version: "7.1.7" )){
	fix = "7.1.7";
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: phpport, data: report );
	exit( 0 );
}
exit( 99 );

