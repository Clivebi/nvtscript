CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800408" );
	script_version( "2021-04-14T11:14:42+0000" );
	script_tag( name: "last_modification", value: "2021-04-14 11:14:42 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "creation_date", value: "2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-0021" );
	script_bugtraq_id( 33150 );
	script_name( "NTP.org 'ntpd' EVP_VerifyFinal() Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/499827" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/499855" );
	script_xref( name: "URL", value: "http://www.ocert.org/advisories/ocert-2008-016.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause spoofing attacks via signature checks on DSA
  and ECDSA keys used with SSL/TLS." );
	script_tag( name: "affected", value: "NTP.org's ntpd version 4.2.4 to 4.2.4p5 and 4.2.5 to 4.2.5p150." );
	script_tag( name: "insight", value: "The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl." );
	script_tag( name: "solution", value: "Upgrade to NTP.org's ntpd version 4.2.4p6 or 4.2.5p151." );
	script_tag( name: "summary", value: "The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to a security bypass vulnerability." );
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
if(( ( revcomp( a: version, b: "4.2.4" ) >= 0 ) && ( revcomp( a: version, b: "4.2.4p5" ) <= 0 ) ) || ( ( revcomp( a: version, b: "4.2.5" ) >= 0 ) && ( revcomp( a: version, b: "4.2.5p150" ) <= 0 ) )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.4p6 or 4.2.5p151", install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

