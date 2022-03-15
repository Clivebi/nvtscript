if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800625" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1828", "CVE-2009-1827" );
	script_bugtraq_id( 35132 );
	script_name( "Mozilla Firefox 'keygen' HTML Tag DOS Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8794" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/50721" );
	script_xref( name: "URL", value: "http://blog.zoller.lu/2009/04/advisory-firefox-denial-of-service.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to cause the browser
to stop responding, infinite loop, application hang, and memory consumption,
and can cause denying service to legitimate users." );
	script_tag( name: "affected", value: "Firefox version 3.0.4 and 3.0.10 on Linux" );
	script_tag( name: "insight", value: "Flaws are due to:

  - Error exists via KEYGEN element in conjunction with a META element
   specifying automatic page refresh or a JavaScript onLoad event handler
   for a BODY element.

  - Error caused while passing a large value in the r (aka Radius) attribute
   of a circle element, related to an 'unclamped loop.'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
to Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Linux/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_is_equal( version: ffVer, test_version: "3.0.10" ) || version_is_equal( version: ffVer, test_version: "3.0.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

