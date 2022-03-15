CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900623" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-0159" );
	script_bugtraq_id( 34481 );
	script_name( "NTP.org 'ntpd' Stack Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34608" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49838" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/0999" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
  code or to cause the application to crash." );
	script_tag( name: "affected", value: "NTP.org's ntpd versions prior to 4.2.4p7-RC2." );
	script_tag( name: "insight", value: "The flaw is due to a boundary error within the cookedprint()
  function in ntpq/ntpq.c while processing malicious response from
  a specially crafted remote time server." );
	script_tag( name: "solution", value: "Upgrade to NTP.org's ntpd version 4.2.4p7-RC2." );
	script_tag( name: "summary", value: "The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to multiple stack buffer overflow vulnerabilities." );
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
if(revcomp( a: version, b: "4.2.4p7-rc2" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.4p7-RC2", install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

