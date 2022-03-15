CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803318" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_cve_id( "CVE-2012-3365" );
	script_bugtraq_id( 54612 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-03-01 12:49:42 +0530 (Fri, 01 Mar 2013)" );
	script_name( "PHP 'open_basedir' Secuirity Bypass Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.php.net/ChangeLog-5.php" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/427459.php" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/cve_reference/CVE-2012-3365" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "php/detected", "Host/runs_windows" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions." );
	script_tag( name: "affected", value: "PHP version before 5.3.15" );
	script_tag( name: "insight", value: "Flaw in SQLite functionality allows attackers to bypass the open_basedir
  protection mechanism." );
	script_tag( name: "solution", value: "Update to PHP 5.3.15 or later." );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "5.3.15" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.15" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

