if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813112" );
	script_version( "2021-05-31T06:00:14+0200" );
	script_cve_id( "CVE-2018-4108", "CVE-2018-4143", "CVE-2018-4105", "CVE-2018-4107", "CVE-2018-4160", "CVE-2018-4167", "CVE-2018-4142", "CVE-2018-4174", "CVE-2018-4131", "CVE-2018-4132", "CVE-2018-4135", "CVE-2018-4111", "CVE-2018-4170", "CVE-2018-4115", "CVE-2018-4157", "CVE-2018-4152", "CVE-2018-4150", "CVE-2018-4138", "CVE-2018-4173" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-05-31 06:00:14 +0200 (Mon, 31 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-04-02 10:46:18 +0530 (Mon, 02 Apr 2018)" );
	script_name( "Apple MacOSX Security Updates(HT208692)-01" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An injection issue due to improper input validation.

  - An issue existed in the parsing of URLs in PDFs due to improper input
    validation.

  - An out-of-bounds read error.

  - An inconsistent user interface issue.

  - By scanning key states, an unprivileged application could log keystrokes
    entered into other applications even when secure input mode was enabled.

  - An issue existed in the handling of S/MIME HTML e-mail.

  - The sysadminctl command-line tool required that passwords be passed to it
    in its arguments, potentially exposing the passwords to other local users.

  - An issue existed in CFPreferences.

  - Multiple memory corruption issues.

  - A validation issue.

  - A consistency issue existed in deciding when to show the microphone use
    indicator." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to execute arbitrary code with kernel privileges,
  gain access to passwords supplied to sysadminctl, truncate an APFS volume
  password, gain access to potentially sensitive data, gain elevated privileges,
  conduct a denial-of-service attack, log keystrokes entered into applications,
  intercept and exfiltrate the contents of S/MIME-encrypted e-mail and use a
  removed configuration profile and access the microphone without indication to
  the user." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.13.x through 10.13.3" );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.13.4 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT208692" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.13" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer || !IsMatchRegexp( osVer, "^10\\.13" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_is_less( version: osVer, test_version: "10.13.4" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.13.4" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

