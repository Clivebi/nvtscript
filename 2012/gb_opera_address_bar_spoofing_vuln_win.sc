if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802450" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_bugtraq_id( 55345 );
	script_cve_id( "CVE-2012-4010" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-09-03 16:35:41 +0530 (Mon, 03 Sep 2012)" );
	script_name( "Opera Address Bar Spoofing Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN69880570/index.html" );
	script_xref( name: "URL", value: "http://www.opera.com/docs/changelogs/windows/1160/" );
	script_xref( name: "URL", value: "http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000080.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_opera_detect_portable_win.sc" );
	script_mandatory_keys( "Opera/Win/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct phishing
  attacks." );
	script_tag( name: "affected", value: "Opera version prior to 11.60 on Windows" );
	script_tag( name: "insight", value: "The flaw is caused due an error in address bar, where certain characters
  displayed in the address bar can be spoofed due to the difficulty in
  determining that the URL displayed in the address bar and the URL being
  accessed are different." );
	script_tag( name: "solution", value: "Upgrade to Opera version 11.60 or later." );
	script_tag( name: "summary", value: "This host is installed with Opera and is prone to address bar
  spoofing vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
operaVer = get_kb_item( "Opera/Win/Version" );
if(!operaVer){
	exit( 0 );
}
if(version_is_less( version: operaVer, test_version: "11.60" )){
	report = report_fixed_ver( installed_version: operaVer, fixed_version: "11.60" );
	security_message( port: 0, data: report );
}

