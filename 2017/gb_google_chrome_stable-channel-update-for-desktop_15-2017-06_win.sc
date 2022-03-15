CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810950" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_cve_id( "CVE-2017-5087", "CVE-2017-5088", "CVE-2017-5089" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-06-16 17:34:30 +0530 (Fri, 16 Jun 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_15-2017-06)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A Sandbox Escape error in IndexedDB.

  - An Out of bounds read error in V8.

  - A Domain spoofing error in Omnibox.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to conduct spoofing attacks,
  bypass security and cause application crash." );
	script_tag( name: "affected", value: "Google Chrome version prior to 59.0.3071.104 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 59.0.3071.104 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/06/stable-channel-update-for-desktop_15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "59.0.3071.104" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "59.0.3071.104" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

