CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103199" );
	script_version( "2021-01-15T14:11:28+0000" );
	script_tag( name: "last_modification", value: "2021-01-15 14:11:28 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2011-08-16 15:29:48 +0200 (Tue, 16 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_bugtraq_id( 49147 );
	script_cve_id( "CVE-2011-2481" );
	script_name( "Apache Tomcat Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49147" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to obtain sensitive
  information." );
	script_tag( name: "affected", value: "Tomcat 7.0.0 through 7.0.16 is vulnerable." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Apache Tomcat is prone to a remote information-disclosure
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
if(version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.16" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.17", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

