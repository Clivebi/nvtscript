CPE = "cpe:/a:apache:jackrabbit";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807898" );
	script_cve_id( "CVE-2016-6801" );
	script_bugtraq_id( 92966 );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-10-06 16:01:40 +0530 (Thu, 06 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Apache Jackrabbit Cross-Site Request Forgery (CSRF) Vulnerability (Linux)" );
	script_tag( name: "summary", value: "This host is running Apache Jackrabbit
  and is prone to a cross-site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in content-type
  check for POST requests which does not handle missing Content-Type header
  fields, nor variations in field values with respect to upper/lower case or
  optional parameters." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct CSRF attacks." );
	script_tag( name: "affected", value: "Apache Jackrabbit 2.4.x before 2.4.6, 2.6.x
  before 2.6.6, 2.8.x before 2.8.3, 2.10.x before 2.10.4, 2.12.x before 2.12.4,
  and 2.13.x before 2.13.3 on linux." );
	script_tag( name: "solution", value: "Upgrade to Apache Jackrabbit 2.4.6 or
  2.6.6 or 2.8.3 or 2.10.4 or 2.12.4 or 2.13.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://issues.apache.org/jira/browse/JCR-4009" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2016/09/14/6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_apache_jackrabbit_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "apache/jackrabbit/installed", "Host/runs_unixoide" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!jackPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: jackPort )){
	exit( 0 );
}
if(( IsMatchRegexp( version, "^(2.4.)" ) ) && version_is_less( version: version, test_version: "2.4.6" )){
	VULN = TRUE;
	fix = "2.4.6";
}
if(( IsMatchRegexp( version, "^(2.6.)" ) ) && version_is_less( version: version, test_version: "2.6.6" )){
	VULN = TRUE;
	fix = "2.6.6";
}
if(( IsMatchRegexp( version, "^(2.8.)" ) ) && version_is_less( version: version, test_version: "2.8.3" )){
	VULN = TRUE;
	fix = "2.8.3";
}
if(( IsMatchRegexp( version, "^(2.10.)" ) ) && version_is_less( version: version, test_version: "2.10.4" )){
	VULN = TRUE;
	fix = "2.10.4";
}
if(( IsMatchRegexp( version, "^(2.12.)" ) ) && version_is_less( version: version, test_version: "2.12.4" )){
	VULN = TRUE;
	fix = "2.12.4";
}
if(( IsMatchRegexp( version, "^(2.13.)" ) ) && version_is_less( version: version, test_version: "2.13.3" )){
	VULN = TRUE;
	fix = "2.13.3";
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix );
	security_message( port: jackPort, data: report );
	exit( 0 );
}
exit( 0 );

