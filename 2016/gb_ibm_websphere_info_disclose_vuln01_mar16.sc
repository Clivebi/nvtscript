CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806884" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2014-3022", "CVE-2014-0965" );
	script_bugtraq_id( 68210, 68211 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:56 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Information Disclosure Vulnerability-01 Mar16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to information-disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to improper handling
  of SOAP responses." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated attackers to obtain sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.0.x before 7.0.0.33, 8.0.x before 8.0.0.9, and 8.5.x before 8.5.5.3." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.33, or 8.0.0.9, or 8.5.5.3, or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21676091" );
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
if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.32" ) ){
	fix = "7.0.0.33";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.8" ) ){
		fix = "8.0.0.9";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.2" )){
			fix = "8.5.5.3";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

