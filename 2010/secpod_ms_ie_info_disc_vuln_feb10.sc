if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900741" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-0652" );
	script_name( "Microsoft Internet Explorer Information Disclosure Vulnerability Feb10" );
	script_xref( name: "URL", value: "http://code.google.com/p/chromium/issues/detail?id=9877" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to obtain sensitive information via
  a crafted stylesheet document." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 8 and prior." );
	script_tag( name: "insight", value: "The flaw exists while handling malformed stylesheet document with incorrect
  MIME type. Microsoft Internet Explorer permits cross-origin loading of CSS
  stylesheets even when the stylesheet download has an incorrect MIME type." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host has Internet Explorer installed and is prone to Information
  Disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(isnull( ieVer )){
	exit( 0 );
}
if(version_is_less_equal( version: ieVer, test_version: "8.0.6001.18702" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

