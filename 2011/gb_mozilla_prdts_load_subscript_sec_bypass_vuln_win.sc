if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802176" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)" );
	script_cve_id( "CVE-2011-3004" );
	script_bugtraq_id( 49852 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Mozilla Firefox and SeaMonkey 'loadSubScript()' Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-43.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_seamonkey_detect_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to gain privileges via a crafted
  web site that leverages certain unwrapping behavior." );
	script_tag( name: "affected", value: "SeaMonkey version prior to 2.4
  Mozilla Firefox version 4.x through 6" );
	script_tag( name: "insight", value: "The flaw is due to an error while handling 'XPCNativeWrappers'
  during calls to the loadSubScript method in an add-on." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/seamonkey and is prone
  to security bypass vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 7.0 or later, Upgrade to SeaMonkey version to 2.4 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_in_range( version: vers, test_version: "4.0", test_version2: "6.0" )){
		report = report_fixed_ver( installed_version: vers, vulnerable_range: "4.0 - 6.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Seamonkey/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "2.4" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "2.4" );
		security_message( port: 0, data: report );
	}
}

