CPE = "cpe:/a:mozilla:firefox:x64";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809809" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-9072" );
	script_bugtraq_id( 94336 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-11-16 12:21:41 +0530 (Wed, 16 Nov 2016)" );
	script_name( "Mozilla Firefox Security Updates (mfsa_2016-89_2016-90)-Windowsx64" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Firefox and is prone to arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to:
  64-bit NPAPI sandbox is not enabled on fresh profile." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox version before
  50 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 50
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2016-89" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver", "SMB/Windows/Arch" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!osArch = get_kb_item( "SMB/Windows/Arch" )){
	exit( 0 );
}
if(!ContainsString( osArch, "x64" )){
	exit( 0 );
}
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "50.0" )){
	report = report_fixed_ver( installed_version: ffVer, fixed_version: "50.0" );
	security_message( data: report );
	exit( 0 );
}

