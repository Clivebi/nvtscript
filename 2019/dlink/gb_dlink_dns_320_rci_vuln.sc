if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114132" );
	script_version( "2021-08-30T08:01:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 08:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-18 14:26:00 +0200 (Wed, 18 Sep 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-16 19:58:00 +0000 (Mon, 16 Sep 2019)" );
	script_cve_id( "CVE-2019-16057" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "D-Link DNS-320 Remote Command Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlink_dns_detect.sc" );
	script_mandatory_keys( "Host/is_dlink_dns_device" );
	script_tag( name: "summary", value: "The D-Link DNS-320 NAS-device is prone to a remote command injection vulnerability." );
	script_tag( name: "insight", value: "The flaw exists in the login module of the device when using a hidden feature
  called SSL Login, for which its required parameter, port, can be poisoned." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "D-Link DNS-320 versions through 2.05.B10." );
	script_tag( name: "solution", value: "Update to version 2.06B01 or later." );
	script_xref( name: "URL", value: "ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DNS-320/REVA/DNS-320_REVA_RELEASE_NOTES_v2.06B01.pdf" );
	script_xref( name: "URL", value: "https://blog.cystack.net/d-link-dns-320-rce/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/o:d-link:dns-320_firmware";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: version, test_version: "2.05.B10" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.06B01", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

