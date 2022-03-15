if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100904" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-11-16 13:35:09 +0100 (Tue, 16 Nov 2010)" );
	script_bugtraq_id( 44862 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0786" );
	script_name( "IBM WebSphere Application Server JAX-WS Denial Of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_websphere_detect.sc" );
	script_mandatory_keys( "ibm_websphere_application_server/installed" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44862" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg27014463" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "IBM WebSphere Application Server is prone to a denial-of-service
  vulnerability." );
	script_tag( name: "impact", value: "Remote attackers can exploit this issue to cause denial-of-service
  conditions for legitimate users." );
	script_tag( name: "affected", value: "Versions prior to IBM WebSphere Application Server 7.0 7.0.0.13 are
  vulnerable." );
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
if(version_in_range( version: vers, test_version: "7", test_version2: "7.0.0.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.0.0.13" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

