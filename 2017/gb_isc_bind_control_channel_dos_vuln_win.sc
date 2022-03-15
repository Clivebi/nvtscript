CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810978" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-3138" );
	script_bugtraq_id( 97657 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-23 11:40:43 +0530 (Tue, 23 May 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ISC BIND Control Channel Denial of Service Vulnerability - Windows" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a feature in named
  which allows operators to issue commands to a running server by communicating
  with the server process over a control channel, using a utility program such
  as rndc." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to cause a denial of service (assertion failure and daemon exit) via
  null command string." );
	script_tag( name: "affected", value: "ISC BIND 9.9.9 through 9.9.9-P7, 9.9.10b1
  through 9.9.10rc2, 9.10.4 through 9.10.4-P7, 9.10.5b1 through 9.10.5rc2,
  9.11.0 through 9.11.0-P4, 9.11.1b1 through 9.11.1rc2, 9.9.9-S1 through
  9.9.9-S9." );
	script_tag( name: "solution", value: "Update to ISC BIND version 9.9.9-P8 or
  9.10.4-P8 or 9.11.0-P5 or 9.9.9-S10 or 9.9.10rc3 or 9.10.5rc3 or 9.11.1rc3
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/aa-01471" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_windows" );
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
if(IsMatchRegexp( version, "^9\\.9" )){
	if( IsMatchRegexp( version, "^9\\.9\\.9" ) && revcomp( a: version, b: "9.9.9p8" ) < 0 ){
		fix = "9.9.9-P8";
	}
	else {
		if( ( revcomp( a: version, b: "9.9.10b1" ) >= 0 ) && ( revcomp( a: version, b: "9.9.10rc3" ) < 0 ) ){
			fix = "9.9.10rc3";
		}
		else {
			if( ( revcomp( a: version, b: "9.10.4" ) >= 0 ) && ( revcomp( a: version, b: "9.10.4p8" ) < 0 ) ){
				fix = "9.10.4-P8";
			}
			else {
				if( ( revcomp( a: version, b: "9.10.5b1" ) >= 0 ) && ( revcomp( a: version, b: "9.10.5rc3" ) < 0 ) ){
					fix = "9.10.5rc3";
				}
				else {
					if( ( revcomp( a: version, b: "9.11.0" ) >= 0 ) && ( revcomp( a: version, b: "9.11.0p5" ) < 0 ) ){
						fix = "9.11.0-P5";
					}
					else {
						if( ( revcomp( a: version, b: "9.11.1b1" ) >= 0 ) && ( revcomp( a: version, b: "9.11.1rc3" ) < 0 ) ){
							fix = "9.10.5rc3";
						}
						else {
							if(( revcomp( a: version, b: "9.9.9s1" ) >= 0 ) && ( revcomp( a: version, b: "9.9.9s10" ) < 0 )){
								fix = "9.9.9-S10";
							}
						}
					}
				}
			}
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( data: report, port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

