CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804563" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1520", "CVE-2014-1522", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532" );
	script_bugtraq_id( 67123, 67125, 67126, 67127, 67129, 67131, 67136, 67132, 67135, 67137, 67134, 67130 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-05-06 15:40:31 +0530 (Tue, 06 May 2014)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 May14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Using certain temp directory within maintenservice_installer.exe in an
  insecure way.

  - An error exists when handling Web Audio.

  - An error exists when validating the XBL status of an object.

  - A use-after-free error exists when processing HTML video in the Text Track
  Manager.

  - An error exists when handling site notifications within the Web Notification
  API.

  - An error exists when handling browser navigations through history to load a
  website.

  - A use-after-free error exists when handling an imgLoader object within the
  'nsGenericHTMLElement::GetWidthHeightForImage()' function.

  - An error exists in NSS.

  - A use-after-free error exists when handling host resolution within the
  'libxul.so!nsHostResolver::ConditionallyRefreshRecord()' function.

  - An error exists when handling the debugging of certain objects.

  - And some unspecified errors exist." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 29.0 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 29.0 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58234" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-34.html" );
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
if(version_is_less( version: ffVer, test_version: "29.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "29.0" );
	security_message( port: 0, data: report );
	exit( 0 );
}

