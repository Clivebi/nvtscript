CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805703" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2014-0230" );
	script_bugtraq_id( 74475 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2015-06-16 15:04:10 +0530 (Tue, 16 Jun 2015)" );
	script_name( "Apache Tomcat Denial Of Service Vulnerability - Jun15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling of
  cases where an HTTP response occurs before finishing the reading of an
  entire request body." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct denial of service attack." );
	script_tag( name: "affected", value: "Apache Tomcat 6.x before 6.0.44,
  7.x before 7.0.55, and 8.x before 8.0.9 on Windows." );
	script_tag( name: "solution", value: "Upgrade to version 6.0.44 or 7.0.55 or
  8.0.9 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2015/04/10/1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
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
if(IsMatchRegexp( appVer, "^6\\.0" )){
	if(version_in_range( version: appVer, test_version: "6.0", test_version2: "6.0.43" )){
		fix = "6.0.44";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( appVer, "^7\\.0" )){
	if(version_in_range( version: appVer, test_version: "7.0", test_version2: "7.0.54" )){
		fix = "7.0.55";
		VULN = TRUE;
	}
}
if(IsMatchRegexp( appVer, "^8\\.0" )){
	if(version_in_range( version: appVer, test_version: "8.0", test_version2: "8.0.8" )){
		fix = "8.0.9";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
	security_message( data: report, port: appPort );
	exit( 0 );
}

