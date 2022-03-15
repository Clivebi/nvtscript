if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801330" );
	script_version( "2020-06-09T10:15:40+0000" );
	script_tag( name: "last_modification", value: "2020-06-09 10:15:40 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)" );
	script_cve_id( "CVE-2010-1852" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Microsoft Internet Explorer Cross Site Data Leakage Vulnerability" );
	script_xref( name: "URL", value: "http://www.cnet.com/8301-31361_1-20004265-254.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow the remote web servers to
  identify specific  persons and their product searches via 'HTTP' request login." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 8 and proir." );
	script_tag( name: "insight", value: "The flaw is due to an error in handling background 'HTTP'
  requests. It uses cookies in possibly unexpected manner when the
  'Invisible Hand extension' is enabled." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Microsoft Internet Explorer web
  browser and is prone to cross site data leakage vulnerability." );
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

