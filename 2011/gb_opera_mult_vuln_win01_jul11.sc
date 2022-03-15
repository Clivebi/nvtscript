if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802111" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)" );
	script_cve_id( "CVE-2011-2628", "CVE-2011-2629", "CVE-2011-2630", "CVE-2011-2631", "CVE-2011-2632", "CVE-2011-2633" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Opera Browser Multiple Vulnerabilities Jul-11 (Windows)" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/992/" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1111/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary
  code and cause a denial of service." );
	script_tag( name: "affected", value: "Opera Web Browser Version prior 11.11" );
	script_tag( name: "insight", value: "The flaws are due to an error

  - In certain frameset constructs, fails to correctly handle when the page
    is unloaded, causing a memory corruption.

  - When reloading page after opening a pop-up of easy-sticky-note extension.

  - In Cascading Style Sheets (CSS) implementation, when handling the
    column-count property.

  - When error when handling destruction of a silver-light instance." );
	script_tag( name: "solution", value: "Upgrade to Opera Web Browser Version 11.11 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Opera browser and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(operaVer){
	if(version_is_less( version: operaVer, test_version: "11.11" )){
		report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.11" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

