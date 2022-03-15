if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803877" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902", "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905" );
	script_bugtraq_id( 61885, 61887, 61891, 61886, 61888, 61889, 61890 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-26 11:59:27 +0530 (Mon, 26 Aug 2013)" );
	script_name( "Google Chrome Multiple Vulnerabilities-01 August13 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to version 29.0.1547.57 or later." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Some unspecified errors exist.

  - An error exists when handling file paths.

  - An integer overflow error exists within ANGLE.

  - Insecure permissions when creating certain shared memory files.

  - Use-after-free error exists within XSLT, media element and document parsing." );
	script_tag( name: "affected", value: "Google Chrome version prior to 29.0.1547.57 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to disclose potentially sensitive
information, compromise a user's system and other attacks may also be possible." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54479" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/08/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "29.0.1547.57" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "29.0.1547.57" );
	security_message( port: 0, data: report );
	exit( 0 );
}

