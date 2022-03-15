CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806892" );
	script_version( "$Revision: 13803 $" );
	script_cve_id( "CVE-2014-3070" );
	script_bugtraq_id( 69296 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2016-03-03 18:23:51 +0530 (Thu, 03 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server Security Bypass Vulnerability-01 Mar16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to Security Bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper account creation
  with the Virtual Member Manager SPI Admin Task addFileRegistryAccount." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to bypass security restrictions." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  8.0.0.6 before 8.0.0.10 and 8.5.x before 8.5.5.3." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 8.0.0.10, or 8.5.5.3, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21681249" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web Servers" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21671835" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!wasVer = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if( version_in_range( version: wasVer, test_version: "8.0.0.6", test_version2: "8.0.0.9" ) ){
	fix = "8.0.0.10";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.2" )){
		fix = "8.5.5.3";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

