if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801370" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)" );
	script_cve_id( "CVE-2010-2660", "CVE-2010-2661", "CVE-2010-2665", "CVE-2010-2666" );
	script_bugtraq_id( 40973 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Opera Browser Multiple Vulnerabilities july-10 (Win02)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40250" );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/962/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/1529" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1054/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause a denial of service or
  execute arbitrary code." );
	script_tag( name: "affected", value: "Opera version prior to 10.54 on Windows." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Fails to restrict certain uses of homograph characters in domain
    names, which makes it easier for remote attackers to spoof IDN domains.

  - Fails to properly restrict access to the full pathname of a file selected
    for upload, which allows attackers to obtain potentially sensitive
    information.

  - Cross site scripting (XSS) vulnerability when handling a data: URI.

  - Fails to properly enforce permission requirements for widget filesystem." );
	script_tag( name: "solution", value: "Upgrade to Opera 10.54 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is installed with Opera web browser and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "10.54" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "10.54" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

