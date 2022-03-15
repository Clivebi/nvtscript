CPE = "cpe:/a:apc:apcupsd";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80014" );
	script_version( "2020-12-08T07:28:20+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 07:28:20 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)" );
	script_bugtraq_id( 2070, 6828, 7200 );
	script_cve_id( "CVE-2001-0040", "CVE-2003-0098", "CVE-2003-0099" );
	script_xref( name: "OSVDB", value: "1683" );
	script_xref( name: "SuSE", value: "SUSE-SA:2003:022" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "apcupsd < 3.8.6 / 3.10.x < 3.10.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Renaud Deraison" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "apcnisd_detect.sc" );
	script_mandatory_keys( "apcupsd/detected" );
	script_tag( name: "vuldetect", value: "Check if a vulnerable version is present
  on the target host." );
	script_tag( name: "summary", value: "The remote apcupsd, according to its version number,
  is vulnerable to multiple vulnerabilities." );
	script_tag( name: "affected", value: "Versions before 3.8.6, and 3.10.x before 3.10.5." );
	script_tag( name: "solution", value: "Update to version 3.8.6, 3.10.5 or later." );
	script_tag( name: "insight", value: "Multiple flaws exist:

  CVE-2001-0040: APC UPS daemon, apcupsd, saves its process ID in a world-writable file.

  CVE-2003-0098: Unknown vulnerability possibly via format strings in a request to a slave server.

  CVE-2003-0099: Multiple buffer overflows related to usage of the vsprintf function." );
	script_tag( name: "impact", value: "CVE-2001-0040: allows local users to kill an arbitrary process by
  specifying the target process ID in the apcupsd.pid file.

  CVE-2003-0098: allows remote attackers to gain root privileges.

  CVE-2003-0099: may allow attackers to cause a denial of service or execute arbitrary code." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( port: port, cpe: CPE )){
	exit( 0 );
}
if( version_is_less( version: vers, test_version: "3.8.6" ) ) {
	fix = "3.8.6";
}
else {
	if(IsMatchRegexp( vers, "^3\\.10\\." ) && version_is_less( version: vers, test_version: "3.10.5" )){
		fix = "3.10.5";
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

