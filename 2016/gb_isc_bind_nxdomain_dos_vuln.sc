CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807241" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_cve_id( "CVE-2016-1284" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-02-09 13:49:30 +0530 (Tue, 09 Feb 2016)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND NXDOMAIN Redirection Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "ISC BIND is prone to a remote denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the 'rdataset.c'
  file when nxdomain-redirect is enabled." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "ISC BIND versions 9.9.8-S1 through 9.9.8-S4." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.8-S5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01348" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc" );
	script_mandatory_keys( "isc/bind/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(version_in_range( version: version, test_version: "9.9.8s1", test_version2: "9.9.8s4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.9.8-S5", install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

