CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806827" );
	script_version( "$Revision: 13803 $" );
	script_cve_id( "CVE-2014-0964" );
	script_bugtraq_id( 67322 );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-02-21 09:24:24 +0100 (Thu, 21 Feb 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-19 13:15:39 +0530 (Tue, 19 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "IBM Websphere Application Server Denial Of Service Vulnerability 01 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to when running the
  Heartbleed scanning tools or if sending specially-crafted Heartbeat
  messages." );
	script_tag( name: "impact", value: "Successful exploitation will allow a remote
  attacker to cause a denial of service via crafted TLS traffic." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  6.1.0.0 through 6.1.0.47 and 6.0.2.0 through 6.0.2.43" );
	script_tag( name: "solution", value: "Apply Interim Fix PI16981 from the vendor" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.scaprepo.com/view.jsp?id=CVE-2014-0964" );
	script_xref( name: "URL", value: "http://www-304.ibm.com/support/docview.wss?uid=swg21673808" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
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
if( version_in_range( version: wasVer, test_version: "6.1", test_version2: "6.1.0.47" ) ){
	fix = "Apply Interim Fix PI16981";
	VULN = TRUE;
}
else {
	if(version_in_range( version: wasVer, test_version: "6.0.2.0", test_version2: "6.0.2.43" )){
		fix = "Apply Interim Fix PI17128";
		VULN = TRUE;
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: fix );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

