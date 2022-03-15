CPE = "cpe:/a:zohocorp:manageengine_firewall_analyzer";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811534" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2015-7780", "CVE-2015-7781" );
	script_bugtraq_id( 78211, 78213 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-30 17:58:00 +0000 (Fri, 30 Jun 2017)" );
	script_tag( name: "creation_date", value: "2017-07-19 14:54:04 +0530 (Wed, 19 Jul 2017)" );
	script_name( "ManageEngine Firewall Analyzer Access Bypass And Directory Traversal Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with ManageEngine
  Firewall Analyzer and is prone to access bypass and directory traversal
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Access permissions are not restricted.

  - A directory traversal error." );
	script_tag( name: "impact", value: "Successfully exploitation will allow remote
  attackers to obtain arbitrary files on the server and bypass security
  restrictions and perform unauthorized actions. This may aid in launching further
  attacks." );
	script_tag( name: "affected", value: "ManageEngine Firewall Analyzer versions prior to 8.0" );
	script_tag( name: "solution", value: "Upgrade to ManageEngine Firewall Analyzer
  8.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN12991684/index.html" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN21968837/index.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_firewall_analyzer_detect.sc" );
	script_mandatory_keys( "me_firewall_analyzer/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!zhport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!zhver = get_app_version( cpe: CPE, port: zhport )){
	exit( 0 );
}
if(version_is_less( version: zhver, test_version: "8.0" )){
	report = report_fixed_ver( installed_version: zhver, fixed_version: "8.0" );
	security_message( data: report, port: zhport );
	exit( 0 );
}
exit( 0 );

