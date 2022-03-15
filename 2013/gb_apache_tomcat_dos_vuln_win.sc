CPE = "cpe:/a:apache:tomcat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803637" );
	script_version( "2019-05-10T11:41:35+0000" );
	script_cve_id( "CVE-2012-3544" );
	script_bugtraq_id( 59797 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-05-10 11:41:35 +0000 (Fri, 10 May 2019)" );
	script_tag( name: "creation_date", value: "2013-06-06 13:10:27 +0530 (Thu, 06 Jun 2013)" );
	script_name( "Apache Tomcat Denial Of Service Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_tomcat_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/tomcat/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/84144" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-6.html" );
	script_xref( name: "URL", value: "http://tomcat.apache.org/security-7.html" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1476592" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1378921" );
	script_xref( name: "URL", value: "http://svn.apache.org/viewvc?view=revision&revision=1378702" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a denial
  of service via a specially crafted request." );
	script_tag( name: "affected", value: "Apache Tomcat version 6.x before 6.0.37 and 7.x before 7.0.30." );
	script_tag( name: "insight", value: "Flaw due to improper validation of an error in the way CRLF sequences at the
  end of data chunks are processed by chunked transfer encoding." );
	script_tag( name: "summary", value: "The host is running Apache Tomcat Server and is prone to denial of
  service vulnerability." );
	script_tag( name: "solution", value: "Apply patch or upgrade Apache Tomcat to 7.0.30 or 6.0.38 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_in_range( version: vers, test_version: "6.0.0", test_version2: "6.0.36" ) || version_in_range( version: vers, test_version: "7.0.0", test_version2: "7.0.29" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.0.37/7.0.30", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

