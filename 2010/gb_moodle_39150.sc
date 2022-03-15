if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100569" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)" );
	script_bugtraq_id( 39150 );
	script_cve_id( "CVE-2010-1619", "CVE-2010-1618", "CVE-2010-1617", "CVE-2010-1616", "CVE-2010-1615", "CVE-2010-1614", "CVE-2010-1613" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Moodle Prior to 1.9.8/1.8.12 Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39150" );
	script_xref( name: "URL", value: "http://docs.moodle.org/en/Moodle_1.9.8_release_notes" );
	script_xref( name: "URL", value: "http://moodle.org/security/" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_moodle_cms_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Moodle/Version" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Moodle is prone to multiple vulnerabilities, including:

  - multiple cross-site scripting issues

  - a security-bypass issue

  - an information-disclosure issue

  - multiple SQL-injection issues

  - an HTML-injection issue

  - a session-fixation issue" );
	script_tag( name: "impact", value: "Attackers can exploit these issues to bypass certain security
restrictions, obtain sensitive information, perform unauthorized
actions, compromise the application, access or modify data, or exploit
latent vulnerabilities in the underlying database. Other attacks may
also be possible." );
	script_tag( name: "affected", value: "These issues affect versions prior to Moodle 1.9.8 and 1.8.12." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(vers = get_version_from_kb( port: port, app: "moodle" )){
	if( IsMatchRegexp( vers, "^1\\.8" ) ){
		if(version_is_less( version: vers, test_version: "1.8.9" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "1.8.9" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
	else {
		if(IsMatchRegexp( vers, "^1\\.9" )){
			if(version_is_less( version: vers, test_version: "1.9.8" )){
				report = report_fixed_ver( installed_version: vers, fixed_version: "1.9.8" );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

