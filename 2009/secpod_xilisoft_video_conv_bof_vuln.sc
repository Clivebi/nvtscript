if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900630" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1370" );
	script_bugtraq_id( 34472 );
	script_name( "Xilisoft Video Converter Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34660" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8452" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/49807" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_xilisoft_video_conv_detect.sc" );
	script_mandatory_keys( "Xilisoft/Video/Conv/Ver" );
	script_tag( name: "impact", value: "This issue can be exploited to corrupt the memory and to execute arbitrary
  code in the context of the affected application." );
	script_tag( name: "affected", value: "Xilisoft Video Converter version 3.x to 3.1.53.0704n and 5.x to 5.1.23.0402
  on Windows." );
	script_tag( name: "insight", value: "The cause is due to an error in ape_plugin.plg when parsing malicious .CUE
  files containing overly long string." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is with installed Xilisoft Video Converter and is prone
  to Buffer Overflow Vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
xsoftVer = get_kb_item( "Xilisoft/Video/Conv/Ver" );
if(!xsoftVer){
	exit( 0 );
}
if(version_in_range( version: xsoftVer, test_version: "3.0", test_version2: "3.1.53.0704n" ) || version_in_range( version: xsoftVer, test_version: "5.0", test_version2: "5.1.23.0402" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

