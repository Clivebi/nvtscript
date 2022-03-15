CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813448" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-1549", "CVE-2018-7182", "CVE-2018-7170", "CVE-2018-7184", "CVE-2018-7185", "CVE-2018-7183", "CVE-2018-12327" );
	script_bugtraq_id( 104517, 88200 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-06-25 17:21:15 +0530 (Mon, 25 Jun 2018)" );
	script_name( "NTP.org 'ntpd' Local Buffer Overflow And Sybil Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_xref( name: "URL", value: "https://gist.github.com/fakhrizulkifli/9b58ed8e0354e8deee50b0eebd1c011f" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/44909" );
	script_xref( name: "URL", value: "http://support.ntp.org/bin/view/Main/NtpBug3505" );
	script_xref( name: "URL", value: "http://support.ntp.org/bin/view/Main/NtpBug3012P12" );
	script_xref( name: "URL", value: "http://www.ntp.org/downloads.html" );
	script_tag( name: "summary", value: "The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to local buffer overflow and sybil vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An insufficient validation of input argument for an IPv4 or IPv6
  command-line parameter.

  - If a system is set up to use a trustedkey and if one is not using the feature
  allowing an optional 4th field in the ntp.keys file to specify which IPs can serve time." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to execute code or escalate to higher privileges and bypass certain security
  restrictions and perform some unauthorized actions to the application.
  This may aid in further attacks." );
	script_tag( name: "affected", value: "NTP.org's ntpd versions 4.x up to, but not including
  4.2.8p12, and 4.3.0 up to, but not including 4.3.94." );
	script_tag( name: "solution", value: "Upgrade to NTP.org's ntpd version 4.2.8p12 or 4.3.94 or
  later. Please see the references for more information." );
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
if(IsMatchRegexp( version, "^4\\." )){
	if( revcomp( a: version, b: "4.2.8p11" ) <= 0 ){
		fix = "4.2.8p12";
	}
	else {
		if(IsMatchRegexp( version, "^4\\.3" ) && ( revcomp( a: version, b: "4.3.94" ) < 0 )){
			fix = "4.3.94";
		}
	}
	if(fix){
		report = report_fixed_ver( installed_version: version, fixed_version: fix, install_path: location );
		security_message( port: port, proto: proto, data: report );
		exit( 0 );
	}
}
exit( 99 );

