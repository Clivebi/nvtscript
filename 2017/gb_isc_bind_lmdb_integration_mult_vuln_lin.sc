CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810958" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2017-06-21 17:50:15 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "ISC BIND LMDB Integration Multiple Vulnerabilities - Linux" );
	script_tag( name: "summary", value: "ISC BIND is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to BIND's use of LMDB." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause some issues regarding zone operations and an unexpected
  application termination." );
	script_tag( name: "affected", value: "ISC BIND 9.11.0 -> 9.11.1.Px (all versions of
  BIND 9.11.0 and 9.11.1)." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.11.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01497" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_unixoide" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(IsMatchRegexp( version, "^9\\.11" ) && revcomp( a: version, b: "9.11.2" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.11.2", install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

