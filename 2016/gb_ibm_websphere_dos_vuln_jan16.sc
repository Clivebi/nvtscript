CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806826" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2012-3330" );
	script_bugtraq_id( 56459 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-28 12:23:12 +0530 (Thu, 28 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Denial of Service Vulnerability Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the proxy
  server component." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to cause a denial of service." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.0 before 7.0.0.27, 8.0 before 8.0.0.5, and 8.5 before 8.5.0.1" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.27, or 8.0.0.5, or 8.5.0.1, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21614265" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "7.0", test_version2: "7.0.0.26" ) ){
	fix = "7.0.0.27";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.4" ) ){
		fix = "8.0.0.5";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.0.0" )){
			fix = "8.5.0.1";
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

