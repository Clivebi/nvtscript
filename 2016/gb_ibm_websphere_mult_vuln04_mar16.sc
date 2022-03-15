CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807621" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-1882", "CVE-2015-0175", "CVE-2015-0174" );
	script_bugtraq_id( 74222, 74223, 74215 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-03-21 14:49:58 +0530 (Mon, 21 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities-04 Mar16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The Run-as user for EJB not being honored under multi-threaded race conditions.

  - An error with the authData elements.

  - An improper handling of configuration data in SNMP implementation." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain elevated privileges on the system, also to obtain
  sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  Liberty Profile 8.5.x before 8.5.5.5." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) Liberty Profile version 8.5.5.5, or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www-01.ibm.com/support/docview.wss?uid=swg21697368" );
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
if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.4" )){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: "8.5.5.5" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

