if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900642" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-1627" );
	script_bugtraq_id( 34712 );
	script_name( "SDP Downloader ASX File Heap Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/34883" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/8536" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1171" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_sdp_downloader_detect.sc" );
	script_mandatory_keys( "SDP/Downloader/Ver" );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to execute arbitrary
code and can cause application crash via a long .asf URL." );
	script_tag( name: "affected", value: "SDP Downloader version 2.3.0 and prior" );
	script_tag( name: "insight", value: "A boundary error exists while processing an HREF attribute of a
REF element in ASX files, due to which application fails to check user supplied
input before copying it into an insufficiently sized buffer." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with SDP Downloader and is prone to
Buffer Overflow vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
sdpVer = get_kb_item( "SDP/Downloader/Ver" );
if(sdpVer != NULL){
	if(version_is_less_equal( version: sdpVer, test_version: "2.3.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

