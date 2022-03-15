if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803624" );
	script_version( "2020-04-21T11:03:03+0000" );
	script_cve_id( "CVE-2013-0912" );
	script_bugtraq_id( 58388 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-21 11:03:03 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2013-05-28 17:26:01 +0530 (Tue, 28 May 2013)" );
	script_name( "Google Chrome Webkit Remote Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/52534" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2013/03/stable-channel-update_7.html" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let the attackers to execute arbitrary code via
  crafted SVG document." );
	script_tag( name: "affected", value: "Google Chrome version prior to 25.0.1364.160 on Linux" );
	script_tag( name: "insight", value: "WebKit contains a type confusion flaw in the 'SVGViewSpec::viewTarget'
  function in WebCore/svg/SVGViewSpec.cpp when handling non-SVG elements." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 25.0.1364.160 or later." );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to remote
  code execution vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "Google-Chrome/Linux/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "25.0.1364.160" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "25.0.1364.160" );
	security_message( port: 0, data: report );
	exit( 0 );
}

