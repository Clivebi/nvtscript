if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802517" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-3647" );
	script_bugtraq_id( 50589 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2011-11-11 15:30:20 +0530 (Fri, 11 Nov 2011)" );
	script_name( "Mozilla Products Privilege Escalation Vulnerabily (Windows)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-46.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_firefox_detect_portable_win.sc", "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Mozilla/Firefox_or_Seamonkey_or_Thunderbird/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to gain privileges via a crafted
  web site that leverages certain unwrapping behavior." );
	script_tag( name: "affected", value: "Thunderbird version prior to 3.1.16
  Mozilla Firefox version prior to 3.6.24" );
	script_tag( name: "insight", value: "The flaws are due to

  - Error in JSSubScriptLoader, which fails to handle XPCNativeWrappers during
    calls to the loadSubScript method in an add-on." );
	script_tag( name: "summary", value: "The host is installed with Mozilla firefox/thunderbird and is prone
  to privilege escalation vulnerability." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 3.6.24 or later, Upgrade to Thunderbird version to 3.1.16 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.6.24" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.24" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
vers = get_kb_item( "Thunderbird/Win/Ver" );
if(vers){
	if(version_is_less( version: vers, test_version: "3.1.16" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "3.1.16" );
		security_message( port: 0, data: report );
	}
}

