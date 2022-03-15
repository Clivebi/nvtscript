CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810290" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_cve_id( "CVE-2016-9147" );
	script_bugtraq_id( 95390 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-27 10:29:00 +0000 (Thu, 27 Sep 2018)" );
	script_tag( name: "creation_date", value: "2017-01-16 16:59:09 +0530 (Mon, 16 Jan 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ISC BIND Inconsistent DNSSEC Information Denial of Service Vulnerability - Windows" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in
  handling a query response containing inconsistent DNSSEC information." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  crafted data." );
	script_tag( name: "affected", value: "ISC BIND 9.9.9-P4, 9.9.9-S6, 9.10.4-P4 and
  9.11.0-P1." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.9-P5 or
  9.9.9-S7 or 9.10.4-P5 or 9.11.0-P2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01440" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
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
if(IsMatchRegexp( version, "^9\\." )){
	if( version_is_equal( version: version, test_version: "9.9.9p4" ) ){
		fix = "9.9.9-P5";
		VULN = TRUE;
	}
	else {
		if( version_is_equal( version: version, test_version: "9.9.9s6" ) ){
			fix = "9.9.9-S7";
			VULN = TRUE;
		}
		else {
			if( version_is_equal( version: version, test_version: "9.10.4p4" ) ){
				fix = "9.10.4-P5";
				VULN = TRUE;
			}
			else {
				if(version_is_equal( version: version, test_version: "9.11.0p1" )){
					fix = "9.11.0-P2";
					VULN = TRUE;
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

