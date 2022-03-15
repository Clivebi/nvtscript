if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.12043" );
	script_version( "2021-05-10T09:07:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-10 09:07:58 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1757" );
	script_bugtraq_id( 9501 );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "BEA WebLogic Operator/Admin Password Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 Astharot" );
	script_family( "Web Servers" );
	script_dependencies( "gb_oracle_weblogic_consolidation.sc" );
	script_mandatory_keys( "oracle/weblogic/detected" );
	script_xref( name: "URL", value: "http://dev2dev.bea.com/resourcelibrary/advisoriesnotifications/BEA04_51.00.jsp" );
	script_xref( name: "URL", value: "https://exchange.xforce.ibmcloud.com/vulnerabilities/14957" );
	script_tag( name: "solution", value: "The vendor has release updates. Please see the references for more information." );
	script_tag( name: "summary", value: "The remote web server is running WebLogic.

  BEA WebLogic Server and WebLogic Express are reported prone to a vulnerability
  that may result in the disclosure of Operator or Admin passwords." );
	script_tag( name: "impact", value: "An attacker who has interactive access to the affected
  managed server, may potentially exploit this issue in a timed attack to harvest credentials
  when the managed server fails during the boot process." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:bea:weblogic_server";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "6.1sp6" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.1 SP6" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "7.0.0.0", test_version2: "7.0sp4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0 SP4" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "8.0.0.0", test_version2: "8.1sp2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.1 SP2" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

