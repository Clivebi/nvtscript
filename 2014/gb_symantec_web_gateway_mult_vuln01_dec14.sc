CPE = "cpe:/a:symantec:web_gateway";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805227" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-5017", "CVE-2014-1650" );
	script_bugtraq_id( 67752, 67753 );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-12-23 11:50:52 +0530 (Tue, 23 Dec 2014)" );
	script_name( "Symantec Web Gateway Multiple Vulnerabilities -01 Dec14" );
	script_tag( name: "summary", value: "This host is installed with Symantec Web
  Gateway and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple errors are due to:

  - An error in user.php script which do not properly sanitize user-supplied
  input before using it in SQL queries.

  - An error in the console interface that is triggered as SNMPConfig.php
  fails to properly sanitize input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject and execute arbitrary commands, and inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or
  disclosure of arbitrary data." );
	script_tag( name: "affected", value: "Symantec Web Gateway prior to version
  5.2.1" );
	script_tag( name: "solution", value: "Upgrade to Symantec Web Gateway version
  5.2.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1030443" );
	script_xref( name: "URL", value: "http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2014&suid=20140616_00" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_symantec_web_gateway_detect.sc" );
	script_mandatory_keys( "symantec_web_gateway/installed" );
	script_xref( name: "URL", value: "http://www.symantec.com/web-gateway/" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!symPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!symVer = get_app_version( cpe: CPE, port: symPort )){
	exit( 0 );
}
if(version_is_less( version: symVer, test_version: "5.2.1" )){
	report = report_fixed_ver( installed_version: symVer, fixed_version: "5.2.1" );
	security_message( port: symPort, data: report );
	exit( 0 );
}

