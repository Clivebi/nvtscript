CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805479" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-0836", "CVE-2015-0833", "CVE-2015-0831", "CVE-2015-0827", "CVE-2015-0822" );
	script_bugtraq_id( 72747, 72742, 72746, 72755, 72756 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-03-03 16:02:28 +0530 (Tue, 03 Mar 2015)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 Mar15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Some unspecified vulnerabilities in the browser engine.

  - Multiple untrusted search path vulnerabilities in updater.exe.

  - Use-after-free error in the 'IDBDatabase::CreateObjectStore' function in
  dom/indexedDB/IDBDatabase.cpp script.

  - Heap-based buffer overflow in the 'mozilla::gfx::CopyRect' and
  'nsTransformedTextRun::SetCapitalization' functions.

  - Flaw in the autocomplete feature for forms." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, bypass certain security
  restrictions, cause a denial of service, execute arbitrary code and local
  privilege escalation." );
	script_tag( name: "affected", value: "Mozilla Thunderbird before version 31.5
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version
  31.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1031791" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-26" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "31.5" )){
	report = "Installed version: " + vers + "\n" + "Fixed version:     31.5\n";
	security_message( data: report );
	exit( 0 );
}

