CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808629" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2016-5388" );
	script_bugtraq_id( 91818 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2016-08-02 11:10:26 +0530 (Tue, 02 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Tomcat 'CGI Servlet' Man-in-the-Middle Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Apache Tomcat
  and is prone to man in the middle attack vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to 'CGI Servlet' does
  not protect applications from the presence of untrusted client data in
  the 'HTTP_PROXY' environment variable." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct MITM attacks on internal server subrequests or direct
  the server to initiate connections to arbitrary hosts." );
	script_tag( name: "affected", value: "Apache Tomcat versions 8.5.4 and prior." );
	script_tag( name: "solution", value: "Information is available and linked in the references
  about a configuration or deployment scenario that helps to reduce the risk of the
  vulnerability." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/BLUU-ABSLHW" );
	script_xref( name: "URL", value: "https://www.apache.org/security/asf-httpoxy-response.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
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
if(version_is_less_equal( version: appVer, test_version: "8.5.4" )){
	report = report_fixed_ver( installed_version: appVer, fixed_version: "Mitigation", install_path: path );
	security_message( data: report, port: appPort );
	exit( 0 );
}

