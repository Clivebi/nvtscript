CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103113" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-09 13:38:24 +0100 (Wed, 09 Mar 2011)" );
	script_bugtraq_id( 46786 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1092" );
	script_name( "PHP 'shmop_read()' Remote Integer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46786" );
	script_xref( name: "URL", value: "http://comments.gmane.org/gmane.comp.security.oss.general/4436" );
	script_xref( name: "URL", value: "http://svn.php.net/viewvc/?view=revision&revision=309018" );
	script_tag( name: "impact", value: "Successful exploits of this vulnerability allow remote attackers to
  execute arbitrary code in the context of a webserver affected by the
  issue. Failed attempts will likely result in denial-of-service conditions." );
	script_tag( name: "affected", value: "Versions prior to PHP 5.3.6 are vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PHP is prone to an integer-overflow vulnerability because it
  fails to ensure that integer values are not overrun." );
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
if(version_in_range( version: vers, test_version: "5.0", test_version2: "5.3.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.6" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

