CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108138" );
	script_version( "2021-09-09T14:06:19+0000" );
	script_cve_id( "CVE-2017-7272" );
	script_bugtraq_id( 97178 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 14:06:19 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-26 02:29:00 +0000 (Mon, 26 Feb 2018)" );
	script_tag( name: "creation_date", value: "2017-04-18 06:00:00 +0200 (Tue, 18 Apr 2017)" );
	script_name( "PHP Server Side Request Forgery Security Bypass Vulnerability (Linux)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-7.php" );
	script_xref( name: "URL", value: "http://bugs.php.net/74216" );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to the php_wddx_pop_element
  function in ext/wddx/wddx.c via an inapplicable class name in a wddxPacket XML document,
  leading to mishandling in a wddx_deserialize call." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to bypass security
  restrictions and perform unauthorized actions. This may aid in further attacks." );
	script_tag( name: "affected", value: "PHP versions 7.0.x before 7.0.18 and 7.1.x before 7.1.4." );
	script_tag( name: "solution", value: "Update to PHP version 7.0.18, 7.1.4
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
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.17" )){
	vuln = TRUE;
	fix = "7.0.18";
}
if(IsMatchRegexp( vers, "^7\\.1" )){
	if(version_is_less( version: vers, test_version: "7.1.4" )){
		vuln = TRUE;
		fix = "7.1.4";
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

