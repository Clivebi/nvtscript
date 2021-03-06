CPE = "cpe:/a:mozilla:bugzilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100482" );
	script_version( "2019-07-05T10:41:31+0000" );
	script_tag( name: "last_modification", value: "2019-07-05 10:41:31 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2010-02-02 21:07:02 +0100 (Tue, 02 Feb 2010)" );
	script_bugtraq_id( 38025 );
	script_cve_id( "CVE-2009-3989" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Bugzilla Directory Access Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38025" );
	script_xref( name: "URL", value: "http://www.bugzilla.org/security/3.0.10/" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "bugzilla_detect.sc" );
	script_mandatory_keys( "bugzilla/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Bugzilla is prone to an information-disclosure vulnerability.

Exploits may allow attackers to obtain potentially sensitive information that may aid in other attacks.

Versions prior to Bugzilla 3.0.11, 3.2.6, 3.4.5, and 3.5.3 are affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "3.0.11" ) || version_in_range( version: vers, test_version: "3.1", test_version2: "3.2.5" ) || version_in_range( version: vers, test_version: "3.3", test_version2: "3.4.4" ) || version_in_range( version: vers, test_version: "3.5", test_version2: "3.5.2" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

