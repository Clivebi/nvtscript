if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817904" );
	script_version( "2021-10-05T08:17:22+0000" );
	script_cve_id( "CVE-2021-1797", "CVE-2021-1760", "CVE-2021-1747", "CVE-2021-1799", "CVE-2021-1759", "CVE-2021-1791", "CVE-2021-1783", "CVE-2021-1741", "CVE-2021-1743", "CVE-2021-1773", "CVE-2021-1778", "CVE-2021-1779", "CVE-2021-1757", "CVE-2021-1764", "CVE-2021-1762", "CVE-2019-20838", "CVE-2020-14155", "CVE-2021-1769", "CVE-2021-1788", "CVE-2021-1765", "CVE-2021-1801", "CVE-2021-1789", "CVE-2021-1871", "CVE-2021-1870" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-09 19:06:00 +0000 (Fri, 09 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-02-03 17:23:29 +0530 (Wed, 03 Feb 2021)" );
	script_name( "Apple MacOSX Security Updates(HT212147)-02" );
	script_tag( name: "summary", value: "Apple Mac OS X is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An improper port validation.

  - An improper access restriction.

  - An improper way of state handling.

  - An improper memory management.

  - An improper iframe sandbox enforcement.

  - Multiple input validation errors.

  - An improper bounds checking in multiple components." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause arbitrary code execution, disclosure of sensitive information and
  denial of service." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 11.x through 11.0.1" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 11.2 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT212147" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("ssh_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^11\\." ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_in_range( version: osVer, test_version: "11.0", test_version2: "11.0.1" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "11.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

