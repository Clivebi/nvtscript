if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11486" );
	script_version( "2021-05-10T09:07:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2003-1095" );
	script_bugtraq_id( 7122, 7124, 7130, 7131 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "WebLogic management servlet" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_mandatory_keys( "oracle/weblogic/detected" );
	script_xref( name: "URL", value: "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA03-28.jsp" );
	script_tag( name: "summary", value: "The remote web server is WebLogic.

  An internal management servlet which does not properly check user credential can be accessed from outside, allowing
  an attacker to change user passwords, and even upload or download any file on the remote server.

  In addition to this, there is a flaw in WebLogic 7.0 which may allow users to delete empty subcontexts." );
	script_tag( name: "solution", value: "- Apply Service Pack 2 Rolling Patch 3 on WebLogic 6.0

  - Apply Service Pack 4 on WebLogic 6.1

  - Apply Service Pack 2 on WebLogic 7.0 or 7.0.0.1." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
CPE = "cpe:/a:oracle:weblogic_server";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0 SP2 RP3" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(IsMatchRegexp( version, "^6\\.0" ) && version_is_less_equal( version: version, test_version: "6.0sp2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0 SP2 RP3" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(IsMatchRegexp( version, "^6\\.1" ) && version_is_less( version: version, test_version: "6.1sp4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1 SP4" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7.0s" ) && version_is_less( version: version, test_version: "7.0sp2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0 SP2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(IsMatchRegexp( version, "^7\\.0\\.0\\.1" ) && version_is_less( version: version, test_version: "7.0.0.1sp2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0.0.1 SP2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

