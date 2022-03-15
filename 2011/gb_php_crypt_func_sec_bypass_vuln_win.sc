CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802329" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-09-07 08:36:57 +0200 (Wed, 07 Sep 2011)" );
	script_cve_id( "CVE-2011-3189" );
	script_bugtraq_id( 48259 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "PHP 'crypt()' Function Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/45678" );
	script_xref( name: "URL", value: "http://www.php.net/archive/2011.php#id2011-08-22-1" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to bypass authentication
  via an arbitrary password." );
	script_tag( name: "affected", value: "PHP version 5.3.7 on Windows" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'crypt()' function which returns the
  salt value instead of hash value when executed with MD5 hash, which allows
  attacker to bypass authentication via an arbitrary password." );
	script_tag( name: "solution", value: "Update to PHP version 5.3.8 or later." );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_equal( version: vers, test_version: "5.3.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.8" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

