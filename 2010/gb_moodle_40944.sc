if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100686" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-21 20:36:15 +0200 (Mon, 21 Jun 2010)" );
	script_bugtraq_id( 40944 );
	script_cve_id( "CVE-2010-2228", "CVE-2010-2229", "CVE-2010-2230", "CVE-2010-2231" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Moodle Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40944" );
	script_xref( name: "URL", value: "http://moodle.org/security/" );
	script_xref( name: "URL", value: "http://moodle.org/mod/forum/discuss.php?d=152366" );
	script_xref( name: "URL", value: "http://moodle.org/mod/forum/discuss.php?d=152367" );
	script_xref( name: "URL", value: "http://moodle.org/mod/forum/discuss.php?d=152368" );
	script_xref( name: "URL", value: "http://moodle.org/mod/forum/discuss.php?d=152369" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Moodle/Version" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Moodle is prone to multiple vulnerabilities, including:

  - a cross-site scripting issue

  - a security-bypass issue

  - an HTML-injection issue" );
	script_tag( name: "impact", value: "Attacker-supplied HTML or JavaScript code could run in the context of
the affected site, potentially allowing an attacker to steal cookie-
based authentication credentials and to control how the site is
rendered to the user, other attacks are also possible." );
	script_tag( name: "affected", value: "These issues affect versions prior to Moodle 1.9.9 and 1.8.13." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "moodle" )){
	if( IsMatchRegexp( vers, "^1\\.8" ) ){
		if(version_is_less( version: vers, test_version: "1.8.13" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.13" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	else {
		if(IsMatchRegexp( vers, "^1\\.9" )){
			if(version_is_less( version: vers, test_version: "1.9.9" )){
				report = report_fixed_ver( installed_version: vers, fixed_version: "1.9.9" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

