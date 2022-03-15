if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801886" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)" );
	script_cve_id( "CVE-2011-0079" );
	script_bugtraq_id( 47657 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Mozilla Firefox Multiple Unspecified Vulnerabilities May-11 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/44357/" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/1127" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-12.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to a cause a denial of
  service or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 4.x before 4.0.1" );
	script_tag( name: "insight", value: "The flaws are due to multiple unspecified errors in the browser engine
  allow remote attackers to cause a denial of service or possibly execute
  arbitrary code via vectors related to gfx/layers/d3d10/ReadbackManagerD3D10.cpp
  and unknown other vectors." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 4.0.1 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to multiple
  unspecified vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "4.0", test_version2: "4.0.b12" )){
		report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "4.0 - 4.0.b12" );
		security_message( port: 0, data: report );
	}
}

