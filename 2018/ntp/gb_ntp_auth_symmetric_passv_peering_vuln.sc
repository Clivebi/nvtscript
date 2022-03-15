CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812793" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-7170" );
	script_bugtraq_id( 103194 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-18 14:01:00 +0000 (Thu, 18 Jun 2020)" );
	script_tag( name: "creation_date", value: "2018-03-07 12:17:55 +0530 (Wed, 07 Mar 2018)" );
	script_name( "NTP.org 'ntpd' Authenticated Symmetric Passive Peering Remote Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_xref( name: "URL", value: "http://support.ntp.org/bin/view/Main/NtpBug3454" );
	script_tag( name: "summary", value: "The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to a remote security vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to if a system is
  set up to use a trustedkey and if one is not using the feature introduced in
  ntp-4.2.8p6 allowing an optional 4th field in the ntp.keys file to specify
  which IPs can serve time." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform some unauthorized
  actions to the application. This may aid in further attacks." );
	script_tag( name: "affected", value: "NTP.org's ntpd version 4.2.x before 4.2.8p7 and 4.3.x before 4.3.92." );
	script_tag( name: "solution", value: "Upgrade to NTP.org's ntpd version 4.2.8p7 or 4.2.8p11
  or 4.3.92." );
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
if( IsMatchRegexp( version, "^4\\.2" ) ){
	if(revcomp( a: version, b: "4.2.8p7" ) < 0){
		fix = "4.2.8p7 or 4.2.8p11";
	}
}
else {
	if(IsMatchRegexp( version, "^4\\.3" )){
		if(revcomp( a: version, b: "4.3.92" ) < 0){
			fix = "4.3.92 or 4.2.8p11";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

