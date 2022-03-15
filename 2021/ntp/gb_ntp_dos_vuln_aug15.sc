CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146233" );
	script_version( "2021-08-17T14:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-07 08:10:44 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-19 15:13:00 +0000 (Mon, 19 Apr 2021)" );
	script_cve_id( "CVE-2015-5219" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NTP < 4.2.7p367 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_tag( name: "summary", value: "NTP is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The ULOGTOD function in ntp.d in SNTP does not properly perform
  type conversions from a precision value to a double, which allows remote attackers to cause a
  denial of service (infinite loop) via a crafted NTP packet." );
	script_tag( name: "affected", value: "NTPd version 4.2.7p366 and prior." );
	script_tag( name: "solution", value: "Update to version 4.2.7p367 or later." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2015/08/25/3" );
	script_xref( name: "URL", value: "https://github.com/ntp-project/ntp/commit/5f295cd05c3c136d39f5b3e500a2d781bdbb59c8" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "4.2.7p367" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2.7p367", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

