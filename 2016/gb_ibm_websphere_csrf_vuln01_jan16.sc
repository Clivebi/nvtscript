CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806843" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-0460" );
	script_bugtraq_id( 57510 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-20 18:21:58 +0530 (Wed, 20 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server CSRF Vulnerability-01 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to Cross-site request forgery(CSRF)
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Flaw is due to an improper validation
  of portlets in the administrative console" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attacker to hijack the authentication of arbitrary users." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  6.1 before 6.1.0.47 and 7.0 before 7.0.0.27" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 6.1.0.47, or 7.0.0.27, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21622444" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "6.1", test_version2: "6.1.0.46" ) ){
	fix = "6.1.0.47";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.26" )){
		fix = "7.0.0.27";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

