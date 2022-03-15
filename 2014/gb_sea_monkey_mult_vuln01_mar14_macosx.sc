CPE = "cpe:/a:mozilla:seamonkey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804529" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514" );
	script_bugtraq_id( 66412, 66419, 66416, 66423, 66421, 66429, 66428, 66422, 66417, 66418, 66426, 66425, 66206, 66207, 66209, 66203, 66240 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-03-27 13:08:31 +0530 (Thu, 27 Mar 2014)" );
	script_name( "SeaMonkey Multiple Vulnerabilities-01 Mar14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with SeaMonkey and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Local users can gain privileges by modifying the extracted Mar contents
  during an update.

  - A boundary error when decoding WAV audio files.

  - The crypto.generateCRMFRequest method does not properly validate a certain
  key type.

  - An error related to certain WebIDL-implemented APIs.

  - An error when performing polygon rendering in MathML.

  - The session-restore feature does not consider the Content Security Policy of
  a data URL.

  - A timing error when processing SVG format images with filters and
  displacements.

  - A use-after-free error when handling garbage collection of TypeObjects under
  memory pressure.

  - An error within the TypedArrayObject implementation when handling neutered
  ArrayBuffer objects.

  - And some unspecified errors exist." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct spoofing attacks,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "SeaMonkey version before 2.25 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to SeaMonkey version 2.25 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57500" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "SeaMonkey/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!smVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: smVer, test_version: "2.25" )){
	report = report_fixed_ver( installed_version: smVer, fixed_version: "2.25" );
	security_message( port: 0, data: report );
	exit( 0 );
}

