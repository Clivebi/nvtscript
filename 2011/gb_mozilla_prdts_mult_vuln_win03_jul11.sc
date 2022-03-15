if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802218" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_cve_id( "CVE-2011-2375" );
	script_bugtraq_id( 48365 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Products Multiple Vulnerabilities July-11 (Windows) - 03" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44972/" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-19.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service." );
	script_tag( name: "affected", value: "Thunderbird versions before 3.1.11
  Mozilla Firefox versions before 5.0" );
	script_tag( name: "insight", value: "Multiple flaws are due to unspecified errors in the browser engine,
  that allow remote attackers to cause a denial of service or possibly execute
  arbitrary code via unknown vectors." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox or Thunderbird and is prone to
  multiple vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 5.0 or later,
  Upgrade to Thunderbird version 3.1.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "5.0" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.1.11" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.11" );
		security_message( port: 0, data: report );
	}
}

