CPE = "cpe:/a:mozilla:bugzilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100358" );
	script_version( "2019-07-24T11:36:46+0000" );
	script_tag( name: "last_modification", value: "2019-07-24 11:36:46 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2009-11-20 12:35:38 +0100 (Fri, 20 Nov 2009)" );
	script_cve_id( "CVE-2009-3386" );
	script_bugtraq_id( 37062 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Bugzilla Bug Alias Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37062" );
	script_xref( name: "URL", value: "http://www.bugzilla.org/security/3.4.3/" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "bugzilla_detect.sc" );
	script_mandatory_keys( "bugzilla/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "Bugzilla is prone to an information-disclosure vulnerability." );
	script_tag( name: "impact", value: "The issue may allow attackers to obtain potentially sensitive
  information that may aid in other attacks." );
	script_tag( name: "affected", value: "Bugzilla 3.3.2 through 3.4.3 Bugzilla 3.5 through 3.5.1" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if( IsMatchRegexp( version, "^3\\.5" ) ){
	if(version_is_less( version: version, test_version: "3.5.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "3.5.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
else {
	if(IsMatchRegexp( version, "^3\\.[34]" )){
		if(version_in_range( version: version, test_version: "3.3.2", test_version2: "3.4.3" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "3.4.4" );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 0 );

