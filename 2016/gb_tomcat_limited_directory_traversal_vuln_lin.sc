CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807411" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2015-5174" );
	script_bugtraq_id( 83329 );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2016-02-25 14:39:41 +0530 (Thu, 25 Feb 2016)" );
	script_name( "Apache Tomcat Limited Directory Traversal Vulnerability - Feb16 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to Limited Directory Traversal Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation of
  path while accessing resources via the ServletContext methods getResource(),
  getResourceAsStream() and getResourcePaths() the paths should be limited to
  the current web application." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  authenticated users to bypass intended SecurityManager restrictions and
  list a parent directory." );
	script_tag( name: "affected", value: "Apache Tomcat 6.x before 6.0.45,
  7.x before 7.0.65, and 8.0.0.RC1 before 8.0.27 on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 6.0.45 or 7.0.65 or
  8.0.27 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-9.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
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
if(IsMatchRegexp( appVer, "^[6-8]\\." )){
	if(version_in_range( version: appVer, test_version: "6.0.0", test_version2: "6.0.44" )){
		fix = "6.0.45";
		VULN = TRUE;
	}
	if(version_in_range( version: appVer, test_version: "7.0.0", test_version2: "7.0.64" )){
		fix = "7.0.65";
		VULN = TRUE;
	}
	if(version_in_range( version: appVer, test_version: "8.0.0", test_version2: "8.0.26" )){
		fix = "8.0.27";
		VULN = TRUE;
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: appPort );
		exit( 0 );
	}
}

