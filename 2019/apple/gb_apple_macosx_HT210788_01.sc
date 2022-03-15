if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815874" );
	script_version( "2021-08-30T13:01:21+0000" );
	script_cve_id( "CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16301", "CVE-2018-16451", "CVE-2018-16452", "CVE-2019-15161", "CVE-2019-15162", "CVE-2019-15163", "CVE-2019-15164", "CVE-2019-15165", "CVE-2019-15166", "CVE-2019-15167" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-11 23:15:00 +0000 (Fri, 11 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-12-12 11:00:05 +0530 (Thu, 12 Dec 2019)" );
	script_name( "Apple MacOSX Security Updates(HT210788)-01" );
	script_tag( name: "summary", value: "This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
  present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A validation issue related to improper input sanitization.

  - An API issue existed in the handling of outgoing phone calls initiated with
    Siri.

  - An issue existed related to improper checks.

  - A buffer overflow issue related to improper bounds checking.

  - An out-of-bounds read error related to improper input validation.

  - An issue existed in the parsing of crafted XML file.

  - Multiple issues in OpenLDAP.

  - Multiple issues in tcpdump.

  - Multiple memory corruption issues related to improper memory handling." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  read restricted memory, execute arbitrary code, conduct denial of service
  attack and disclosure of user information." );
	script_tag( name: "affected", value: "Apple Mac OS X versions 10.15.x prior to 10.15.2." );
	script_tag( name: "solution", value: "Upgrade to Apple Mac OS X 10.15.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT210788" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
if(!osVer || !IsMatchRegexp( osVer, "^10\\.15" ) || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
if(version_is_less( version: osVer, test_version: "10.15.2" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.15.2" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

