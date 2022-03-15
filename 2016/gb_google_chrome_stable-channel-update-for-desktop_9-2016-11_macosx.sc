CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809098" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_cve_id( "CVE-2016-5199", "CVE-2016-5200", "CVE-2016-5201", "CVE-2016-5202" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2016-11-16 17:47:43 +0530 (Wed, 16 Nov 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop_9-2016-11)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The heap corruption error in FFmpeg.

  - An out of bounds memory access error in V8.

  - An info leak error in extensions.

  - The various fixes from internal audits, fuzzing and other initiatives" );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to corrupt memory, to access
  sensitive information and to cause the application crash." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 54.0.2840.98 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  54.0.2840.98 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://googlechromereleases.blogspot.in/2016/11/stable-channel-update-for-desktop_9.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: chr_ver, test_version: "54.0.2840.98" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "54.0.2840.98" );
	security_message( data: report );
	exit( 0 );
}

