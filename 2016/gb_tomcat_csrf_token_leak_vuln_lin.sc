CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807410" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2015-5351" );
	script_bugtraq_id( 83330 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-02-25 14:34:55 +0530 (Thu, 25 Feb 2016)" );
	script_name( "Apache Tomcat CSRF Token Leak Vulnerability - Feb16 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to CSRF Token Leak Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in index page
  of the Manager and Host Manager applications included a valid CSRF token when
  issuing a redirect ." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass a CSRF protection mechanism by using a token." );
	script_tag( name: "affected", value: "Apache Tomcat 7.0.1 before 7.0.68,
  8.0.0.RC1 before 8.0.32, and 9.0.0.M1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to version 7.0.68, or 8.0.32 or
  9.0.0.M3 or later." );
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
	if(version_in_range( version: appVer, test_version: "7.0.1", test_version2: "7.0.67" )){
		fix = "7.0.68";
		VULN = TRUE;
	}
	if(version_in_range( version: appVer, test_version: "8.0.0.RC1", test_version2: "8.0.30" )){
		fix = "8.0.32";
		VULN = TRUE;
	}
	if(version_is_equal( version: appVer, test_version: "9.0.0.M1" )){
		fix = "9.0.0.M3";
		VULN = TRUE;
	}
	if(VULN){
		report = report_fixed_ver( installed_version: appVer, fixed_version: fix, install_path: path );
		security_message( data: report, port: appPort );
		exit( 0 );
	}
}
