CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807651" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2015-1936" );
	script_bugtraq_id( 75480 );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-04-12 18:40:51 +0530 (Tue, 12 Apr 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Session Hijack Vulnerability Apr16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to session hijack vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in
  administrative console." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to hijack a user's session on the system." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  8.0.0 before 8.0.0.12 and 8.5 before 8.5.5.6" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) 8.0.0.12, 8.5.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21959083" );
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
if( version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.5" ) ){
	fix = "8.5.5.6";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.11" )){
		fix = "8.0.0.12";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

