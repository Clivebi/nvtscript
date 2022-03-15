CPE = "cpe:/a:isc:bind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106292" );
	script_version( "2021-03-26T13:22:13+0000" );
	script_tag( name: "last_modification", value: "2021-03-26 13:22:13 +0000 (Fri, 26 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-09-28 09:42:23 +0700 (Wed, 28 Sep 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_cve_id( "CVE-2016-2775" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ISC BIND lwresd Denial of Service Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_isc_bind_consolidation.sc" );
	script_mandatory_keys( "isc/bind/detected" );
	script_tag( name: "summary", value: "ISC BIND is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The lwresd component in ISC BIND (which is not enabled by default)
  could crash while processing an overlong request name. This could lead to a denial of service." );
	script_tag( name: "impact", value: "An remote attacker may cause a denial of service condition." );
	script_tag( name: "solution", value: "Update to 9.9.9-P1, 9.10.4-P1, 9.11.0b1 or later." );
	script_xref( name: "URL", value: "https://kb.isc.org/article/AA-01393" );
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
if(!IsMatchRegexp( version, "^9\\." )){
	exit( 99 );
}
if( IsMatchRegexp( version, "^9\\.9\\.[3-9]s[0-9]" ) ){
	if(version_is_less( version: version, test_version: "9.9.9s3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.9.9-S3", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
else {
	if(version_is_less( version: version, test_version: "9.9.9p2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.9.9-P2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(version_in_range( version: version, test_version: "9.10.0", test_version2: "9.10.4p1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.10.4-P2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
	if(( revcomp( a: version, b: "9.11.0a3" ) >= 0 ) && ( revcomp( a: version, b: "9.11.0b1" ) <= 0 )){
		report = report_fixed_ver( installed_version: version, fixed_version: "9.11.0b2", install_path: location );
		security_message( port: port, data: report, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

