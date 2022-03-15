if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900836" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3003" );
	script_name( "Microsoft Internet Explorer Address Bar Spoofing Vulnerability" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/EXE/Ver" );
	script_tag( name: "impact", value: "Successful exploitation lets the attackers to spoof parts of the
  address bar and modify page content on a host that a user may consider partly trusted." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 6.x, 7.x and 8.x." );
	script_tag( name: "insight", value: "Error exists when opening a new window using 'window.open()'
  which can be exploited to display spoofed content in the browser window while
  the address bar shows an arbitrary path on a possibly trusted host." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Internet Explorer and is prone to
  Address Bar Spoofing vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/EXE/Ver" );
if(!ieVer){
	exit( 0 );
}
if(version_in_range( version: ieVer, test_version: "6.0", test_version2: "6.0.3790.3959" ) || version_in_range( version: ieVer, test_version: "7.0", test_version2: "7.0.6000.16876" ) || version_in_range( version: ieVer, test_version: "8.0", test_version2: "8.0.6001.18702" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

