CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810764" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-5648" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-20 21:15:00 +0000 (Mon, 20 Jul 2020)" );
	script_tag( name: "creation_date", value: "2017-04-21 15:51:01 +0530 (Fri, 21 Apr 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Apache Tomcat 'SecurityManager' Information Disclosure Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A some calls to application listeners
  did not use the appropriate facade object. When running an untrusted
  application under a SecurityManager, it was therefore possible for
  that untrusted application to retain a reference to the request or
  response object and thereby access and/or modify information associated
   with another web application." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to obtain sensitive information from requests other then their own." );
	script_tag( name: "affected", value: "Apache Tomcat versions 9.0.0.M1 to 9.0.0.M17,

  Apache Tomcat versions 8.5.0 to 8.5.11,

  Apache Tomcat versions 8.0.0.RC1 to 8.0.41 and

  Apache Tomcat versions 7.0.0 to 7.0.75 on Windows" );
	script_tag( name: "solution", value: "Upgrade to version 9.0.0.M18,
  8.5.12, 8.0.42, 7.0.76 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://lists.apache.org/thread.html/d0e00f2e147a9e9b13a6829133092f349b2882bf6860397368a52600@%3Cannounce.tomcat.apache.org%3E" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( tomPort = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: tomPort, exit_no_version: TRUE )){
	exit( 0 );
}
appVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( appVer, "^[7-9]\\." )){
	if( version_in_range( version: appVer, test_version: "7.0.0", test_version2: "7.0.75" ) ){
		fix = "7.0.76";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: appVer, test_version: "8.5.0", test_version2: "8.5.11" ) ){
			fix = "8.5.12";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: appVer, test_version: "8.0.0.RC1", test_version2: "8.0.41" ) ){
				fix = "8.0.42";
				VULN = TRUE;
			}
			else {
				if(version_in_range( version: appVer, test_version: "9.0.0.M1", test_version2: "9.0.0.M17" )){
					fix = "9.0.0.M18";
					VULN = TRUE;
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: tomPort );
		exit( 0 );
	}
}

