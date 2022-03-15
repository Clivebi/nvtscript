CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805755" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-7327", "CVE-2015-7180", "CVE-2015-7177", "CVE-2015-7176", "CVE-2015-7175", "CVE-2015-7174", "CVE-2015-4522", "CVE-2015-4521", "CVE-2015-4520", "CVE-2015-4519", "CVE-2015-4517", "CVE-2015-4516", "CVE-2015-4511", "CVE-2015-4510", "CVE-2015-4509", "CVE-2015-4508", "CVE-2015-4507", "CVE-2015-4506", "CVE-2015-4504", "CVE-2015-4503", "CVE-2015-4502", "CVE-2015-4501", "CVE-2015-4500" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-09-29 18:11:28 +0530 (Tue, 29 Sep 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities - Sep15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are exists due to:

  - Failed to  restrict the availability of High Resolution Time API times,

  - Multiple memory corruption flaws,

  - 'js/src/proxy/Proxy.cpp' mishandles certain receiver arguments,

  - Multiple unspecified errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  and remote attackers to cause a denial of service or possibly execute arbitrary
  code, gain privileges and some unspecified impacts." );
	script_tag( name: "affected", value: "Mozilla Firefox version before 41.0 on
  Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 41.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-114/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: ffVer, test_version: "41.0" )){
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + "41.0" + "\n";
	security_message( data: report );
	exit( 0 );
}
