CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811124" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2016-5177", "CVE-2016-5178" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-05-26 10:35:26 +0530 (Fri, 26 May 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_29-2016-09)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Use after free in V8.

  - Various fixes from internal audits, fuzzing and other initiatives." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers corrupt memory, to bypass security, to reduce performance, to bypass
  the SafeBrowsing protection mechanism, to cause a denial of service and other
  unspecified impact." );
	script_tag( name: "affected", value: "Google Chrome version prior to 53.0.2785.143 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 53.0.2785.143 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://googlechromereleases.blogspot.in/2016/09/stable-channel-update-for-desktop_29.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "53.0.2785.143" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "53.0.2785.143" );
	security_message( data: report );
	exit( 0 );
}

