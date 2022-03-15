if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801506" );
	script_version( "2020-10-23T13:29:00+0000" );
	script_tag( name: "last_modification", value: "2020-10-23 13:29:00 +0000 (Fri, 23 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_bugtraq_id( 42775 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3002", "CVE-2010-2996" );
	script_name( "RealNetworks RealPlayer Multiple Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61426" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/61424" );
	script_xref( name: "URL", value: "http://service.real.com/realplayer/security/08262010_player/en/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_realplayer_detect_win.sc" );
	script_mandatory_keys( "RealPlayer/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  codes within the context of the application." );
	script_tag( name: "affected", value: "RealNetworks RealPlayer 11.0 to 11.1 on Windows platform." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Array index error in the player, which allows attackers to execute
    arbitrary code via a malformed header in a RealMedia '.IVR' file.

  - Unspecified errors in the player, which allows attackers to bypass
    intended access restrictions on files via unknown vectors." );
	script_tag( name: "solution", value: "Upgrade to RealPlayer SP version 1.1.5." );
	script_tag( name: "summary", value: "This host is installed with RealPlayer which is prone to multiple
  vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
rpVer = get_kb_item( "RealPlayer/Win/Ver" );
if(isnull( rpVer )){
	exit( 0 );
}
if(version_in_range( version: rpVer, test_version: "11.0.0", test_version2: "11.0.0.674" )){
	report = report_fixed_ver( installed_version: rpVer, vulnerable_range: "11.0.0 - 11.0.0.674" );
	security_message( port: 0, data: report );
}

