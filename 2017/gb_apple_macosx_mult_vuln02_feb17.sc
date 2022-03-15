if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810568" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2016-8670", "CVE-2016-9933", "CVE-2016-9934", "CVE-2017-2353", "CVE-2017-2358", "CVE-2017-2361", "CVE-2017-2357", "CVE-2017-2370", "CVE-2017-2360", "CVE-2016-8687", "CVE-2016-1248" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-02 01:29:00 +0000 (Sat, 02 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-02-28 09:04:00 +0530 (Tue, 28 Feb 2017)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities-02 February-2017" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An input validation issue existed in modelines.

  - A buffer overflow issue in libarchive.

  - A use after free issue in Kernel.

  - A memory initialization issue in IOAudioFamily.

  - A cross-site scripting issue in Help Viewer.

  - A memory corruption issue in Graphics Drivers.

  - A use after free issue in Bluetooth.

  - Some unspecified issues in apache_mod_php module." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code or cause a denial of service, gain access to
  potentially sensitive information." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.12.x before
  10.12.3" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X version
  10.12.3 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207483" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.12" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(version_in_range( version: osVer, test_version: "10.12", test_version2: "10.12.2" )){
		report = report_fixed_ver( installed_version: osVer, fixed_version: "10.12.3" );
		security_message( data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

