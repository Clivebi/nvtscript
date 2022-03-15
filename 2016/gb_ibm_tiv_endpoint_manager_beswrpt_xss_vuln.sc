CPE = "cpe:/a:ibm:tivoli_endpoint_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809369" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2016-0293" );
	script_bugtraq_id( 92593 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-10-18 13:23:56 +0530 (Tue, 18 Oct 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Tivoli Endpoint Manager 'beswrpt' Cross Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with IBM Tivoli
  Endpoint Manager and is prone to cross site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of
  contents of .beswrpt file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML." );
	script_tag( name: "affected", value: "IBM Tivoli Endpoint Manager versions
  9.x before 9.1.8 and 9.2.x before 9.2.8" );
	script_tag( name: "solution", value: "Upgrade to IBM Tivoli Endpoint Manager
  version 9.1.8, or 9.2.8, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21985743" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ibm_endpoint_manager_web_detect.sc" );
	script_mandatory_keys( "ibm_endpoint_manager/installed" );
	script_require_ports( "Services/www", 52311 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!tivPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!tivVer = get_app_version( cpe: CPE, port: tivPort )){
	exit( 0 );
}
if( version_in_range( version: tivVer, test_version: "9.0", test_version2: "9.1.7" ) ){
	fix = "9.1.8";
	VULN = TRUE;
}
else {
	if(version_in_range( version: tivVer, test_version: "9.2", test_version2: "9.2.7" )){
		fix = "9.2.8";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: tivVer, fixed_version: fix );
	security_message( port: tivPort, data: report );
	exit( 0 );
}

