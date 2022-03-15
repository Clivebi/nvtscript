CPE = "cpe:/a:ibm:websphere_application_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806836" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2013-4006" );
	script_bugtraq_id( 63786 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-01-20 10:43:54 +0530 (Wed, 20 Jan 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM Websphere Application Server Information Disclosure Vulnerability Jan16" );
	script_tag( name: "summary", value: "This host is installed with IBM Websphere
  application server and is prone to unspecified remote information-disclosure
  vulnerability" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an insecure permissions
  of files created by the Liberty Server." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  A remote attacker to obtain sensitive information." );
	script_tag( name: "affected", value: "IBM WebSphere Application Server (WAS)
  Liberty Profile 8.5 before 8.5.5.1." );
	script_tag( name: "solution", value: "Upgrade to IBM WebSphere Application
  Server (WAS) version 8.5.5.1 or later." );
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
if(version_in_range( version: wasVer, test_version: "8.5", test_version2: "8.5.5.0" )){
	report = report_fixed_ver( installed_version: wasVer, fixed_version: "8.5.5.1" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

