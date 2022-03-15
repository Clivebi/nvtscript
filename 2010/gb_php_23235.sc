CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100593" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-04-21 13:10:07 +0200 (Wed, 21 Apr 2010)" );
	script_bugtraq_id( 23235 );
	script_cve_id( "CVE-2007-1888", "CVE-2007-1887" );
	script_name( "PHP sqlite_udf_decode_binary() Function Buffer Overflow Vulnerability" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/23235" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php#5.2.3" );
	script_xref( name: "URL", value: "http://www.php-security.org/MOPB/MOPB-41-2007.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/481830" );
	script_tag( name: "impact", value: "An attacker can exploit this issue to execute arbitrary machine code
  in the context of the affected webserver. Failed exploit attempts will
  likely crash the webserver, denying service to legitimate users." );
	script_tag( name: "affected", value: "This issue affects PHP versions prior to 4.4.5 and 5.2.1." );
	script_tag( name: "solution", value: "Reports indicate that the vendor released versions 4.4.5 and 5.2.1 to
  address this issue. Please contact the vendor for information on
  obtaining and applying fixes.

  The reporter of this issue indicates that if you are using a shared
  copy of an external Sqlite library, you will remain vulnerable to this
  issue, even after upgrading to nonvulnerable versions." );
	script_tag( name: "summary", value: "PHP is prone to a buffer-overflow vulnerability because the
  application fails to perform boundary checks before copying
  user-supplied data to insufficiently sized memory buffers." );
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
if( IsMatchRegexp( vers, "^4\\.4" ) ){
	if(version_is_less( version: vers, test_version: "4.4.5" )){
		vuln = TRUE;
		fix = "4.4.5";
	}
}
else {
	if(IsMatchRegexp( vers, "^5\\.2" )){
		if(version_is_less( version: vers, test_version: "5.2.1" )){
			vuln = TRUE;
			fix = "5.2.1";
		}
	}
}
if(vuln){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

