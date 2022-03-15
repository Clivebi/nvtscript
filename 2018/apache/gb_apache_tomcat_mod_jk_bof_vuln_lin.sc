CPE = "cpe:/a:apache:mod_jk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812787" );
	script_version( "2021-07-13T07:23:07+0000" );
	script_cve_id( "CVE-2016-6808" );
	script_bugtraq_id( 93429 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-13 07:23:07 +0000 (Tue, 13 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-02-27 10:49:53 +0530 (Tue, 27 Feb 2018)" );
	script_name( "Apache Tomcat JK Connector (mod_jk) 1.2.0 - 1.2.41 Buffer Overflow Vulnerability - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_apache_mod_jk_http_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/mod_jk/detected", "Host/runs_unixoide" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/139071" );
	script_tag( name: "summary", value: "Apache Tomcat JK Connector (mod_jk) is prone to a buffer
  overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as IIS/ISAPI specific code implements special
  handling when a virtual host is present. The virtual host name and the URI are concatenated to
  create a virtual host mapping rule. The length checks prior to writing to the target buffer for
  this rule did not take account of the length of the virtual host name." );
	script_tag( name: "impact", value: "Successfully exploiting this issue will allow remote attackers to
  execute arbitrary code in the context of the user running the application. Failed exploit attempts
  will likely result in denial-of-service conditions." );
	script_tag( name: "affected", value: "Apache Tomcat JK Connector (mod_jk) version 1.2.0 through
  1.2.41." );
	script_tag( name: "solution", value: "Update to version 1.2.42 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
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
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "1.2.0", test_version2: "1.2.41" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.2.42", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

