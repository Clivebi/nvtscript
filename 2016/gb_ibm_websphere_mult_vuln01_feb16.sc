CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806873" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-4938", "CVE-2015-1932" );
	script_bugtraq_id( 76466, 76463 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-02-16 17:20:05 +0530 (Tue, 16 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities-01 Feb16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple Unspecified vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct spoofing attacks, to obtain sensitive information that
  may lead to further attacks." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.x before 7.0.0.39, 8.0.x before 8.0.0.11, and 8.5.x before 8.5.5.7." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.39, or 8.0.0.11, or 8.5.5.7, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21963275" );
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
if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.38" ) ){
	fix = "7.0.0.39";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.10" ) ){
		fix = "8.0.0.11";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.6" )){
			fix = "8.5.5.7";
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

