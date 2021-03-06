CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805019" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2014-0119" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2014-11-28 19:52:03 +0530 (Fri, 28 Nov 2014)" );
	script_name( "Apache Tomcat XML External Entity Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59732" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is
  prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an application does
  not properly constrain the class loader that accesses the XML parser used
  with an XSLT stylesheet" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to read arbitrary files via a crafted web application that provides
  an XML external entity declaration in conjunction with an entity reference." );
	script_tag( name: "affected", value: "Apache Tomcat before 6.0.40, 7.x before 7.0.54, and 8.x before 8.0.6" );
	script_tag( name: "solution", value: "Upgrade to version 6.0.40, 7.0.54, 8.0.6 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.39" ) || version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.53" ) || version_in_range( version: vers, test_version: "8.0.0.RC1", test_version2: "8.0.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.40/7.0.53/8.0.5", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

