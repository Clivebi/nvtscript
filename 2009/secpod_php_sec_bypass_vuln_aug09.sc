CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900835" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2008-7002" );
	script_bugtraq_id( 31064 );
	script_name( "PHP Security Bypass Vulnerability - Aug09" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/383831.php" );
	script_xref( name: "URL", value: "http://downloads.securityfocus.com/vulnerabilities/exploits/31064.php" );
	script_tag( name: "impact", value: "Successful exploitation will let the local attacker execute arbitrary code and
  can bypass security restriction in the context of the web application." );
	script_tag( name: "affected", value: "PHP version 5.2.5." );
	script_tag( name: "insight", value: "Error exists when application fails to enforce 'safe_mode_exec_dir' and
  'open_basedir' restrictions for certain functions, which can be caused via
  the exec, system, shell_exec, passthru, or popen functions, possibly
  involving pathnames such as 'C:' drive notation." );
	script_tag( name: "solution", value: "Update to PHP version 5.3.2 or later." );
	script_tag( name: "summary", value: "PHP is prone to a security bypass vulnerability." );
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
if(version_is_equal( version: vers, test_version: "5.2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.2" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

