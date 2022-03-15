CPE = "cpe:/a:php:php";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100529" );
	script_version( "2021-04-13T14:13:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-03-15 13:03:19 +0100 (Mon, 15 Mar 2010)" );
	script_bugtraq_id( 38708 );
	script_cve_id( "CVE-2010-0397" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "PHP xmlrpc Extension Multiple Remote Denial of Service Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "secpod_php_smb_login_detect.sc", "gb_php_ssh_login_detect.sc", "gb_php_http_detect.sc" );
	script_mandatory_keys( "php/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38708" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=573573" );
	script_xref( name: "URL", value: "http://permalink.gmane.org/gmane.comp.security.oss.general/2673" );
	script_tag( name: "impact", value: "Exploiting these issues allows remote attackers to cause denial-of-
  service conditions in the context of an application using the
  vulnerable library." );
	script_tag( name: "affected", value: "PHP 5.3.1 is vulnerable. Other versions may also be affected." );
	script_tag( name: "summary", value: "PHP's xmlrpc extension library is prone to multiple denial-of-
  service vulnerabilities because it fails to properly handle crafted
  XML-RPC requests." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_is_equal( version: vers, test_version: "5.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "N/A" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

