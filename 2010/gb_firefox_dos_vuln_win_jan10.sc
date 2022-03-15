if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800416" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2010-0220" );
	script_name( "Firefox 'nsObserverList::FillObserverArray' DOS Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://isc.sans.org/diary.html?storyid=7897" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=507114" );
	script_xref( name: "URL", value: "http://www.mozilla.com/en-US/firefox/3.5.7/releasenotes" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful remote exploitation will allow attackers to  crash application
  via a crafted web site that triggers memory consumption and an accompanying
  Low Memory alert dialog, and also triggers attempted removal of an observer from an empty observers array." );
	script_tag( name: "affected", value: "Mozilla Firefox version prior to 3.5.7 on Windows." );
	script_tag( name: "insight", value: "The flaw is due to error in 'nsObserverList::FillObserverArray()' function
  in 'xpcom/ds/nsObserverList.cpp'" );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.5.7" );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone to
  Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
firefoxVer = get_kb_item( "Firefox/Win/Ver" );
if(!firefoxVer){
	exit( 0 );
}
if(version_is_less( version: firefoxVer, test_version: "3.5.7" )){
	report = report_fixed_ver( installed_version: firefoxVer, fixed_version: "3.5.7" );
	security_message( port: 0, data: report );
}

