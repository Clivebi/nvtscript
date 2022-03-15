CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803781" );
	script_version( "2021-01-15T14:11:28+0000" );
	script_cve_id( "CVE-2010-3718" );
	script_bugtraq_id( 46177 );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2013-11-27 15:51:40 +0530 (Wed, 27 Nov 2013)" );
	script_name( "Apache Tomcat SecurityManager Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/65159" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1025025" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is prone to security bypass
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade Apache Tomcat version to 5.5.30, 6.0.30, 7.0.4 or later." );
	script_tag( name: "insight", value: "The flaw is due to the ServletContect attribute being improperly restricted
  to read-only setting." );
	script_tag( name: "affected", value: "Apache Tomcat version 5.5.x before 5.5.30
  Apache Tomcat version 6.0.x before 6.0.30
  Apache Tomcat version 7.0.x before 7.0.4" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to bypass certain
  authentication and obtain sensitive information." );
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
if(version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.3" ) || version_in_range( version: vers, test_version: "5.5.0", test_version2: "5.5.29" ) || version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.29" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.5.30/6.0.30/7.0.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

