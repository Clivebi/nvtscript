CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100684" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-06-21 20:36:15 +0200 (Mon, 21 Jun 2010)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-2225" );
	script_bugtraq_id( 40948 );
	script_name( "PHP 'SplObjectStorage' Unserializer Arbitrary Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40948" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=605641" );
	script_tag( name: "impact", value: "Successful exploits will compromise the application and possibly
  the computer." );
	script_tag( name: "affected", value: "PHP 5 through 5.3.2 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "PHP is prone to a vulnerability that an attacker could exploit to
  execute arbitrary code with the privileges of the user running the
  affected application." );
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
if(version_in_range( version: vers, test_version: "5", test_version2: "5.3.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.3" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

