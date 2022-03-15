if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803380" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-1383", "CVE-2013-1384", "CVE-2013-1385", "CVE-2013-1386" );
	script_bugtraq_id( 58980, 58982, 58983, 58984 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-04-19 10:20:42 +0530 (Fri, 19 Apr 2013)" );
	script_name( "Adobe Shockwave Player Multiple Vulnerabilities -01 April 13 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/52981" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb13-12.html" );
	script_xref( name: "URL", value: "http://cert-mu.gov.mu/English/Pages/Vulnerability%20Notes/2013/VN-2013-93.aspx" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_player_detect.sc" );
	script_mandatory_keys( "Adobe/ShockwavePlayer/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause obtain
  sensitive information, remote code execution, and corrupt system memory." );
	script_tag( name: "affected", value: "Adobe Shockwave Player Version 12.0.0.112 and prior on Windows" );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Unknown errors in unspecified vectors.

  - Buffer overflow via unspecified vectors.

  - Does not prevent access to address information, which makes it easy to
    bypass the ASLR protection mechanism." );
	script_tag( name: "solution", value: "Upgrade to version 12.0.2.122 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Adobe/ShockwavePlayer/Ver" );
if(vers){
	if(version_is_less_equal( version: vers, test_version: "12.0.0.112" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 12.0.0.112" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

