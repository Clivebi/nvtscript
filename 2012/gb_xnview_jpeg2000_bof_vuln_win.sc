if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802816" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2012-1051" );
	script_bugtraq_id( 51896 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2012-03-15 16:28:54 +0530 (Thu, 15 Mar 2012)" );
	script_name( "XnView JPEG2000 Plugin Buffer Overflow Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_xnview_detect_win.sc" );
	script_mandatory_keys( "XnView/Win/Ver" );
	script_tag( name: "summary", value: "This host has XnView installed and is prone to a buffer overflow
  vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to an error in the JPEG2000 plugin in Xjp2.dll, when
  processing a JPEG2000 (JP2) file with a crafted Quantization Default (QCD)
  marker segment." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application or cause a denial of service
  condition." );
	script_tag( name: "affected", value: "XnView version 1.98.5 and prior." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/73040" );
	exit( 0 );
}
require("version_func.inc.sc");
xnviewVer = get_kb_item( "XnView/Win/Ver" );
if(isnull( xnviewVer )){
	exit( 0 );
}
if(version_is_less_equal( version: xnviewVer, test_version: "1.98.5" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

