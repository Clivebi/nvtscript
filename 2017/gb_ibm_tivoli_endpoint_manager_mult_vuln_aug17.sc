CPE = "cpe:/a:ibm:tivoli_endpoint_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811270" );
	script_version( "2021-09-15T08:01:41+0000" );
	script_cve_id( "CVE-2017-1227", "CVE-2016-0729", "CVE-2016-8617", "CVE-2016-8624", "CVE-2016-8621" );
	script_bugtraq_id( 100073, 83423, 94097, 94103, 94101 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 08:01:41 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-08-03 13:58:40 +0530 (Thu, 03 Aug 2017)" );
	script_name( "IBM Tivoli Endpoint Manager Multiple Vulnerabilities-Aug17" );
	script_tag( name: "summary", value: "This host is installed with IBM Tivoli
  Endpoint Manager and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Under certain conditions the size or amount of memory resources that are
    requested or influenced by an actor is not restricted.

  - Multiple buffer overflows errors exist in internal/XMLReader.cpp,
    util/XMLURL.cpp and util/XMLUri.cpp in the XML Parser library in Apache Xerces-C.

  - A buffer overflow error exists in cURL/libcURL.

  - An invalid URL parsing in cURL/libcURL.

  - A read out of bounds error in 'curl_getdate'" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to consume more resources than reasonably intended, resulting in a
  crash or segmentation fault, bypass certain security restrictions and gain
  access to potentially sensitive information." );
	script_tag( name: "affected", value: "IBM Tivoli Endpoint Manager (BigFix Platform)
  9.1 prior to patch 10, 9.2 prior to patch 10 and 9.5 prior to patch 5" );
	script_tag( name: "solution", value: "Upgrade to IBM Tivoli Endpoint Manager
  (BigFix Platform) 9.1 patch 10 or 9.2 patch 10 or 9.5 patch 5 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg22003222" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ibm_endpoint_manager_web_detect.sc" );
	script_mandatory_keys( "ibm_endpoint_manager/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ibmPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ibmVersion = get_app_version( cpe: CPE, port: ibmPort )){
	exit( 0 );
}
if( IsMatchRegexp( ibmVersion, "^(9\\.1\\.)" ) && version_is_less( version: ibmVersion, test_version: "9.1.1314.0" ) ){
	fix = "9.1.1314.0";
}
else {
	if( IsMatchRegexp( ibmVersion, "^(9\\.2\\.)" ) && version_is_less( version: ibmVersion, test_version: "9.2.10.25" ) ){
		fix = "9.2.10.25";
	}
	else {
		if(IsMatchRegexp( ibmVersion, "^(9\\.5\\.)" ) && version_is_less( version: ibmVersion, test_version: "9.5.5.193" )){
			fix = "9.5.5.193";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: ibmVersion, fixed_version: fix );
	security_message( port: ibmPort, data: report );
	exit( 0 );
}
exit( 0 );

