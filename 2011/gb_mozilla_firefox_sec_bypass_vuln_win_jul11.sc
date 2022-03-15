if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802215" );
	script_version( "2020-11-12T09:50:32+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:50:32 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_cve_id( "CVE-2011-2370" );
	script_bugtraq_id( 48380 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Mozilla Firefox Security Bypass Vulnerability July-11 (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=645699" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2011/mfsa2011-28.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to trigger an installation
  dialog for an add-on or theme." );
	script_tag( name: "affected", value: "Mozilla Firefox versions before 5.0." );
	script_tag( name: "insight", value: "The flaw is due to firefox does not properly enforce the whitelist
  for the xpinstall functionality, which allows a non-whitelisted site to
  trigger an install dialog for add-ons and themes." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 5.0 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to security bypass
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_is_less( version: ffVer, test_version: "5.0" )){
		report = report_fixed_ver( installed_version: ffVer, fixed_version: "5.0" );
		security_message( port: 0, data: report );
	}
}

