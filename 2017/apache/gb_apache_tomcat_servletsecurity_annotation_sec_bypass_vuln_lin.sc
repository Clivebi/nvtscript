CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812257" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2011-1088", "CVE-2011-1419" );
	script_bugtraq_id( 46685 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2017-12-12 13:08:44 +0530 (Tue, 12 Dec 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'ServletSecurity' Annotations Security Bypass Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to a security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to when a web application
  was started, ServletSecurity annotations were ignored. This meant that some
  areas of the application may not have been protected as expected." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain authentication and obtain sensitive information." );
	script_tag( name: "affected", value: "Apache Tomcat versions 7.0.0 to 7.0.10
  on Linux" );
	script_tag( name: "solution", value: "Upgrade to Tomcat version 7.0.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.11" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/517013/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
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
if(IsMatchRegexp( appVer, "^7\\." )){
	if(version_is_less( version: appVer, test_version: "7.0.11" )){
		report = report_fixed_ver( installed_version: appVer, fixed_version: "7.0.11", install_path: path );
		security_message( data: report, port: tomPort );
		exit( 0 );
	}
}
exit( 0 );

