CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807414" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2016-0763" );
	script_bugtraq_id( 83326 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2016-02-25 14:43:49 +0530 (Thu, 25 Feb 2016)" );
	script_name( "Apache Tomcat Security Manager Bypass Vulnerability - Feb16 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to Security Manager Bypass Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  'ResourceLinkFactory.setGlobalContext()' method and is accessible by web
   applications running under a security manager without any checks." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to bypass intended SecurityManager restrictions and read
  or write to arbitrary application data, or cause a denial of service." );
	script_tag( name: "affected", value: "Apache Tomcat 7.0.0 before 7.0.68,
  8.0.0.RC1 before 8.0.31, and 9.0.0.M1 before 9.0.0.M2 on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 7.0.68 or
  8.0.32 or 9.0.0.M3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_unixoide" );
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
if(IsMatchRegexp( appVer, "^[7-9]\\." )){
	if(version_in_range( version: appVer, test_version: "7.0.0", test_version2: "7.0.67" )){
		fix = "7.0.68";
		VULN = TRUE;
	}
	if(version_in_range( version: appVer, test_version: "8.0.0.RC1", test_version2: "8.0.30" )){
		fix = "8.0.32";
		VULN = TRUE;
	}
	if(version_in_range( version: appVer, test_version: "9.0.0.M1", test_version2: "9.0.0.M2" )){
		fix = "9.0.0.M3";
		VULN = TRUE;
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: appPort );
		exit( 0 );
	}
}

