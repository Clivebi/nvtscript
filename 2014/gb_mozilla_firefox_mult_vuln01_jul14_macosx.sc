CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804703" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536", "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1539", "CVE-2014-1540", "CVE-2014-1541", "CVE-2014-1542", "CVE-2014-1543" );
	script_bugtraq_id( 67965, 67964, 67966, 67967, 67971, 67976, 67978, 67979, 67968, 67969 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-07-01 13:58:34 +0530 (Tue, 01 Jul 2014)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 July14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error in the 'PropertyProvider::FindJustificationRange()' function.

  - An error in the 'navigator.getGamepads()' method within the Gamepad API.

  - An error when handling cursor rendering related to an embedded flash object

  - A use-after-free error in the 'mozilla::dom::workers::WorkerPrivateParent' class.

  - A use-after-free error in the 'nsEventListenerManager::CompileEventHandlerInternal()'
  function.

  - A boundary error related to AudioBuffer channel counts and sample rate range
  within the Web Audio Speex resampler.

  - And some unspecified errors exist." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct clickjacking attacks
and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 30.0 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 30.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59171" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-48.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Mozilla/Firefox/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "30.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "30.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

