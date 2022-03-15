if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902636" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-3900" );
	script_bugtraq_id( 50701 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-11 11:11:11 +0530 (Fri, 11 Nov 2011)" );
	script_name( "Google Chrome V8 Remote Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46889/" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2011/11/stable-channel-update_16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service." );
	script_tag( name: "affected", value: "Google Chrome version prior to 15.0.874.121 on Linux" );
	script_tag( name: "insight", value: "The flaw is due to an out-of-bounds write operation error in V8
  (JavaScript engine) causing memory corruption." );
	script_tag( name: "solution", value: "Upgrade to the Google Chrome 15.0.874.121 or later." );
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
if(version_is_less( version: chromeVer, test_version: "15.0.874.121" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "15.0.874.121" );
	security_message( port: 0, data: report );
}

