CPE = "cpe:/a:ntp:ntp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150696" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-21 09:34:21 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2001-0414" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "NTP < 4.2 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "ntp_open.sc", "gb_ntp_detect_lin.sc" );
	script_mandatory_keys( "ntpd/version/detected" );
	script_tag( name: "summary", value: "Buffer overflow in ntpd ntp daemon 4.0.99k and earlier (aka
  xntpd and xntp3) allows remote attackers to cause a denial of service and possibly execute
  arbitrary commands via a long readvar argument." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "NTPd through version 4.0.99k." );
	script_tag( name: "solution", value: "Update to version 4.2 or later." );
	script_xref( name: "URL", value: "http://support.ntp.org/bin/view/Main/SecurityNotice#June_2001_Buffer_overflow_in_ntp" );
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
if(version_is_less( version: version, test_version: "4.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.2", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

