CPE = "cpe:/a:apple:icloud";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811252" );
	script_version( "2021-09-15T09:01:43+0000" );
	script_cve_id( "CVE-2017-7010", "CVE-2017-7013", "CVE-2017-7018", "CVE-2017-7020", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042", "CVE-2017-7043", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7052", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7049", "CVE-2017-7064", "CVE-2017-7019", "CVE-2017-7012" );
	script_bugtraq_id( 99889, 99879, 99885, 99890 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-15 09:01:43 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-22 19:27:00 +0000 (Fri, 22 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-07-20 12:15:28 +0530 (Thu, 20 Jul 2017)" );
	script_name( "Apple iCloud Multiple Vulnerabilities-HT207921 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iCloud
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An out-of-bounds read in libxml2.

  - Multiple memory corruption issues in WebKit.

  - A memory initialization issue in WebKit." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code and gain access to potentially sensitive
  information." );
	script_tag( name: "affected", value: "Apple iCloud versions before 6.2.2
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Apple iCloud 6.2.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.apple.com/en-us/HT207927" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_apple_icloud_detect_win.sc" );
	script_mandatory_keys( "apple/icloud/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!icVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: icVer, test_version: "6.2.2.39" )){
	report = report_fixed_ver( installed_version: icVer, fixed_version: "6.2.2" );
	security_message( data: report );
	exit( 0 );
}

