if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803675" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-2866" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-06-24 11:15:34 +0530 (Mon, 24 Jun 2013)" );
	script_name( "Google Chrome Clickjacking Vulnerability June13 (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028694" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/06/stable-channel-update_18.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to obtain sensitive information
  and conduct clickjacking attacks against the users Flash configuration." );
	script_tag( name: "affected", value: "Google Chrome version prior to 27.0.1453.116 on Windows" );
	script_tag( name: "insight", value: "Flaw within Flash plug-in which does not properly determine whether a user
  wishes to permit camera or microphone access by a Flash application." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 27.0.1453.116 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to
  Clickjacking vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "27.0.1453.116" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "27.0.1453.116" );
	security_message( port: 0, data: report );
}

