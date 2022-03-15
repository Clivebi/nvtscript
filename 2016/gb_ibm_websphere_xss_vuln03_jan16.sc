CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806840" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-4004" );
	script_bugtraq_id( 61935 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-20 14:48:51 +0530 (Wed, 20 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Cross Site Scripting Vulnerability -03 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to XSS vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insufficient
  validation of input by Administrative Console." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote authenticated users to inject arbitrary web script or HTML via
  unspecified vectors." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  versions 8.0 before 8.0.0.7 and 8.5 before 8.5.5.1" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 8.0.0.7, or 8.5.5.1, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21644047" );
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
if( version_in_range( version: wasVer, test_version: "8.0", test_version2: "8.0.0.6" ) ){
	fix = "8.0.0.7";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.0" )){
		fix = "8.5.5.1";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

