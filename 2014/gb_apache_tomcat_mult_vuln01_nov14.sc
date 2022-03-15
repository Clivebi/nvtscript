CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805018" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-11-28 19:36:20 +0530 (Fri, 28 Nov 2014)" );
	script_name( "Apache Tomcat Multiple Vulnerabilities - 01 Nov14" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc" );
	script_mandatory_keys( "apache/tomcat/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/60729" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-8.html" );
	script_tag( name: "summary", value: "This host is running Apache Tomcat and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An  Integer overflow in the parseChunkHeader function in
  java/org/apache/coyote/http11/filters/ChunkedInputFilter.java

  - The java/org/apache/catalina/servlets/DefaultServlet.java in the default
  servlet in does not properly restrict XSLT stylesheets.

  - Integer overflow in java/org/apache/tomcat/util/buf/Ascii.java in
  when operated behind a reverse proxy" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (resource consumption), bypass
  security-manager restrictions and read arbitrary files, conduct HTTP request
  smuggling attacks via a crafted Content-Length HTTP header." );
	script_tag( name: "affected", value: "Apache Tomcat before 6.0.40, 7.x before 7.0.53, and 8.x before 8.0.4" );
	script_tag( name: "solution", value: "Upgrade to version 6.0.40, 7.0.53, 8.0.4 or later." );
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
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.39" ) || version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.52" ) || version_in_range( version: vers, test_version: "8.0.0", test_version2: "8.0.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.40/7.0.53/8.0.4", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

