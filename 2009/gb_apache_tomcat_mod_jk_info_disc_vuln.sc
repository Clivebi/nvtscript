CPE = "cpe:/a:apache:mod_jk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800277" );
	script_version( "2021-07-13T07:23:07+0000" );
	script_tag( name: "last_modification", value: "2021-07-13 07:23:07 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "creation_date", value: "2009-04-17 09:00:01 +0200 (Fri, 17 Apr 2009)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-5519" );
	script_bugtraq_id( 34412 );
	script_name( "Apache Tomcat JK Connector (mod_jk) 1.2.0 - 1.2.26 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_mod_jk_http_detect.sc" );
	script_mandatory_keys( "apache/mod_jk/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34621" );
	script_xref( name: "URL", value: "http://marc.info/?l=tomcat-dev&m=123913700700879" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Apr/1022001.html" );
	script_tag( name: "summary", value: "Apache Tomcat JK Connector (mod_jk) is prone to an information
  disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "This issue can be exploited to disclose response data associated
  with the request of a different user via specially crafted HTTP requests and to gain sensitive
  information about the remote host." );
	script_tag( name: "affected", value: "Apache Tomcat JK Connector (mod_jk) version 1.2.0 through 1.2.26." );
	script_tag( name: "insight", value: "This flaw is due to:

  - an error when handling empty POST requests with a non-zero 'Content-Length' header.

  - an error while handling multiple noncompliant AJP protocol related requests." );
	script_tag( name: "solution", value: "Update to version 1.2.27 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.26" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.2.27", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

