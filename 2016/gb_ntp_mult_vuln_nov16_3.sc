CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106407" );
	script_version( "2021-04-14T11:14:42+0000" );
	script_cve_id( "CVE-2016-7434" );
	script_tag( name: "last_modification", value: "2021-04-14 11:14:42 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_name( "NTP.org 'ntpd' DoS Vulnerability (Nov 2016 - 1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/633847" );
	script_tag( name: "summary", value: "NTP.org's reference implementation of NTP server, ntpd, is prone to a
  denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "If ntpd is configured to allow mrulist query requests from a server that
  sends a crafted malicious packet, ntpd will crash on receipt of that crafted malicious mrulist query packet." );
	script_tag( name: "impact", value: "A remote attacker may be able to perform a denial of service on ntpd." );
	script_tag( name: "affected", value: "Version 4.2.7p22 up to 4.2.8p8, 4.3.0 up to 4.3.93." );
	script_tag( name: "solution", value: "Upgrade to NTP.org's ntpd version 4.2.8p9, 4.3.94 or later." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_full( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
proto = infos["proto"];
if(( revcomp( a: version, b: "4.2.7p22" ) >= 0 ) && ( revcomp( a: version, b: "4.2.8p9" ) < 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.8p9", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
if(( revcomp( a: version, b: "4.3.0" ) >= 0 ) && ( revcomp( a: version, b: "4.3.94" ) < 0 )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.3.94", install_path: location );
	security_message( port: port, data: report, proto: proto );
	exit( 0 );
}
exit( 99 );

