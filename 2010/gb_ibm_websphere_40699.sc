if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100671" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-06-10 10:47:44 +0200 (Thu, 10 Jun 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-2326" );
	script_bugtraq_id( 40699 );
	script_name( "IBM WebSphere Application Server 'addNode.log' Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/40699" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1PM10684" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg1PM15830" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "IBM WebSphere Application Server (WAS) is prone to an information-
  disclosure vulnerability." );
	script_tag( name: "impact", value: "A local authenticated attacker can exploit this issue to gain access
  to sensitive information. This may aid in further attacks." );
	script_tag( name: "affected", value: "Versions prior to WAS 7.0.0.11 are vulnerable." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:ibm:websphere_application_server";
if(!vers = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "7.0", test_version2: "7.0.0.10" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.0.11" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

