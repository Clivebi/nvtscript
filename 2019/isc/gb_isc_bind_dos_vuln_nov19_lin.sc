CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143161" );
	script_version( "2021-08-30T11:01:18+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 11:01:18 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-11-22 02:45:53 +0000 (Fri, 22 Nov 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_cve_id( "CVE-2019-6477" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND DoS Vulnerability (CVE-2019-6477) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "isc/bind/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability as TCP-pipelined
  queries can bypass tcp-clients limit." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "By design, BIND is intended to limit the number of TCP clients that can be
  connected at any given time. The update to this functionality introduced by CVE-2018-5743 changed how BIND
  calculates the number of concurrent TCP clients from counting the outstanding TCP queries to counting the TCP
  client connections. On a server with TCP-pipelining capability, it is possible for one TCP client to send a
  large number of DNS requests over a single connection. Each outstanding query will be handled internally as an
  independent client request, thus bypassing the new TCP clients limit." );
	script_tag( name: "impact", value: "With pipelining enabled each incoming query on a TCP connection requires a
  similar resource allocation to a query received via UDP or via TCP without pipelining enabled. A client using a
  TCP-pipelined connection to a server could consume more resources than the server has been provisioned to handle.
  When a TCP connection with a large number of pipelined queries is closed, the load on the server releasing these
  multiple resources can cause it to become unresponsive, even for queries that can be answered authoritatively
  or from cache." );
	script_tag( name: "affected", value: "BIND 9.11.6-P1 - 9.11.12, 9.12.4-P1 - 9.12.4-P2, 9.14.1 - 9.14.7 and
  9.11.5-S6 - 9.11.12-S1. Also affects all releases in the 9.15 development branch." );
	script_tag( name: "solution", value: "Update to version 9.11.13, 9.14.8, 9.15.6, 9.11.13-S1 or later." );
	script_xref( name: "URL", value: "https://kb.isc.org/docs/cve-2019-6477" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
location = infos["location"];
if(!IsMatchRegexp( version, "^9\\." )){
	exit( 99 );
}
if( IsMatchRegexp( version, "^9\\.11\\.[0-9]s[0-9]" ) ){
	if(version_in_range( version: version, test_version: "9.11.5s6", test_version2: "9.11.12s1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.13-S1", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_in_range( version: version, test_version: "9.11.6p1", test_version2: "9.11.12" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.13", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.12.4p1", test_version2: "9.12.4p2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.14.8", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.14.1", test_version2: "9.14.7" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.14.8", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.15.0", test_version2: "9.15.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.15.6", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

