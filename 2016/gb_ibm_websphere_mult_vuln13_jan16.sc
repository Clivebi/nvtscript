CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806845" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-0565", "CVE-2013-0540" );
	script_bugtraq_id( 59252, 59246 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-20 15:54:07 +0530 (Wed, 20 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Multiple Vulnerabilities -13 Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Liberty Profile does not properly validate authentication cookies, when SSL
    is not enabled.

  - improper validation of user supplied input by the RPCAdapter for the Web2.0
    and Mobile toolkit" );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attacker to bypass intended access restrictions, to inject arbitrary
  web script or HTML via a crafted response." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  8.5 before 8.5.0.2" );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 8.5.0.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.0.1" )){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: "8.5.0.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

