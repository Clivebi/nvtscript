CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900021" );
	script_version( "2021-08-18T10:41:57+0000" );
	script_tag( name: "last_modification", value: "2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-08-07 17:25:16 +0200 (Thu, 07 Aug 2008)" );
	script_bugtraq_id( 30494, 30496 );
	script_cve_id( "CVE-2008-1232", "CVE-2008-2370" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_name( "Apache Tomcat Cross-Site Scripting and Security Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31379/" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/31381/" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat web server, which is prone to
  cross site scripting and security bypass vulnerabilities." );
	script_tag( name: "insight", value: "The flaws are due to:

  - input validation error in the method HttpServletResponse.sendError() which
  fails to properly sanitise before being returned to the user in the HTTP Reason-Phrase.

  - the application fails to normalize the target path before removing
  the query string when using a RequestDispatcher." );
	script_tag( name: "affected", value: "Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26, and 6.0.0 - 6.0.16." );
	script_tag( name: "solution", value: "Upgrade to a later version of 4.x, 5.x, or 6.x series." );
	script_tag( name: "impact", value: "Successful exploitation could cause execution of arbitrary
  HTML code, script code, and information disclosure." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( appPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: appPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( appVer, "^4\\.1" )){
	if(version_in_range( version: appVer, test_version: "4.1.0", test_version2: "4.1.37" )){
		fix = "4.1.38";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( appVer, "^5\\.5" )){
	if(version_in_range( version: appVer, test_version: "5.5.0", test_version2: "5.5.26" )){
		fix = "5.5.27";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( appVer, "^6\\.0" )){
	if(version_in_range( version: appVer, test_version: "6.0.0", test_version2: "6.0.16" )){
		fix = "6.0.17";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: appPort );
	exit( 0 );
}
exit( 99 );

