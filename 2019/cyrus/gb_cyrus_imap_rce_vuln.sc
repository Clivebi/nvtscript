CPE = "cpe:/a:cyrus:imap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142504" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-06-26 01:36:48 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-14 05:15:00 +0000 (Wed, 14 Oct 2020)" );
	script_cve_id( "CVE-2019-11356" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Cyrus IMAP 2.5.x < 2.5.13, 3.0.x < 3.0.10 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_cyrus_imap_server_detect.sc" );
	script_mandatory_keys( "cyrus/imap_server/detected" );
	script_tag( name: "summary", value: "Cyrus IMAP is prone to a remote code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The CalDAV feature in httpd in Cyrus IMAP allows remote attackers to execute
  arbitrary code via a crafted HTTP PUT operation for an event with a long iCalendar property name." );
	script_tag( name: "affected", value: "Cyrus IMAP versions 2.5.0 to 2.5.12 and 3.0.0 to 3.0.9." );
	script_tag( name: "solution", value: "Update to version 2.5.13, 3.0.10 or later." );
	script_xref( name: "URL", value: "https://www.cyrusimap.org/imap/download/release-notes/2.5/x/2.5.13.html" );
	script_xref( name: "URL", value: "https://www.cyrusimap.org/imap/download/release-notes/3.0/x/3.0.10.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "2.5", test_version2: "2.5.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.5.13" );
	security_message( port: 0, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "3.0", test_version2: "3.0.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.0.10" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

