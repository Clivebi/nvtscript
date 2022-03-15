CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803782" );
	script_version( "2021-01-15T14:11:28+0000" );
	script_cve_id( "CVE-2011-0534" );
	script_bugtraq_id( 46164 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2013-11-27 16:07:10 +0530 (Wed, 27 Nov 2013)" );
	script_name( "Apache Tomcat NIO Connector Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65162" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1025027" );
	script_xref( name: "URL", value: "http://cxsecurity.com/issue/WLB-2011020145" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is prone to denial of service
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade Apache Tomcat version to 6.0.32, 7.0.8 or later." );
	script_tag( name: "insight", value: "Tomcat did not enforce the maxHttpHeaderSize limit while parsing the request
  line in the NIO HTTP connector. A specially crafted request could trigger an DoS via an OutOfMemoryError." );
	script_tag( name: "affected", value: "Apache Tomcat version 6.0.x before 6.0.32
  Apache Tomcat version 7.0.x before 7.0.8" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to trigger a
  denial-of-service condition in the affected software." );
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
if(version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.7" ) || version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.31" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.32/7.0.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

