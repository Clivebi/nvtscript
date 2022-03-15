CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806831" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-6325", "CVE-2013-6725" );
	script_bugtraq_id( 65099, 65096 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-19 15:54:16 +0530 (Tue, 19 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities -06 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - improper handling of requests by a web services endpoint.

  - improper validation of input in the Administrative Console." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attacker to inject arbitrary web script or HTML and to cause a denial
  of service (resource consumption)." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  7.x before 7.0.0.31, 8.0.x before 8.0.0.8, and 8.5.x before 8.5.5.2" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 7.0.0.31, or 8.0.0.8, or 8.5.5.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21661323" );
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
if( version_in_range( version: wasVer, test_version: "7", test_version2: "7.0.0.30" ) ){
	fix = "7.0.0.31";
	VULN = TRUE;
}
else {
	if( version_in_range( version: wasVer, test_version: "8", test_version2: "8.0.0.7" ) ){
		fix = "8.0.0.8";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.1" )){
			fix = "8.5.0.2";
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

