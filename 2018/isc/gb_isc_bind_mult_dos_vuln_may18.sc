CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813401" );
	script_version( "2021-05-28T06:00:18+0200" );
	script_cve_id( "CVE-2018-5736", "CVE-2018-5737" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-05-28 06:00:18 +0200 (Fri, 28 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-05-22 09:25:41 +0530 (Tue, 22 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND Multiple Denial of Service Vulnerabilities (May 2018)" );
	script_tag( name: "summary", value: "ISC BIND is prone to multiple denial of service vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in zone database reference counting while attempting several
    transfers of a slave zone in quick succession.

  - An error in the implementation of the new serve-stale feature." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure or degradation)." );
	script_tag( name: "affected", value: "ISC BIND versions 9.12.0 and 9.12.1." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.12.1-P2 or
  later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01606" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01602" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(version == "9.12.0" || version == "9.12.1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.12.1-P2", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

