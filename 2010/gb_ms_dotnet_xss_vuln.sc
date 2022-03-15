if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801345" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_cve_id( "CVE-2010-2085" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Microsoft .NET 'ASP.NET' Cross-Site Scripting vulnerability" );
	script_xref( name: "URL", value: "https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt" );
	script_xref( name: "URL", value: "http://www.blackhat.com/presentations/bh-dc-10/Byrne_David/BlackHat-DC-2010-Byrne-SGUI-slides.pdf" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_dependencies( "remote-detect-MSdotNET-version.sc" );
	script_mandatory_keys( "dotNET/install", "aspNET/installed", "dotNET/version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to conduct cross-site scripting
  attacks against the form control via the __VIEWSTATE parameter." );
	script_tag( name: "affected", value: "Microsoft .NET version prior to 1.1." );
	script_tag( name: "insight", value: "The flaw is due to error in the default configuration of 'ASP.NET' it
  has a value of FALSE for the EnableViewStateMac property when processing the
 '__VIEWSTATE' parameter." );
	script_tag( name: "solution", value: "Upgrade to Microsoft .NET 1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "The host is running Microsoft .NET and is prone to Cross-Site
  Scripting Vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
dotNet = get_kb_item( "dotNET/install" );
if(!dotNet){
	exit( 0 );
}
apsdotNet = get_kb_item( "aspNET/installed" );
if(!aspdotNet){
	exit( 0 );
}
dotNet = get_kb_item( "dotNET/version" );
if(!dotNet){
	exit( 0 );
}
if(version_is_less( version: dotNet, test_version: "1.1" )){
	report = report_fixed_ver( installed_version: dotNet, fixed_version: "1.1" );
	security_message( port: 0, data: report );
}

