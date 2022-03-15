if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900597" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-2566" );
	script_name( "TFM MMPlayer '.m3u' Buffer Overflow Vulnerability - July-09" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_tfm_mmplayer_detect.sc" );
	script_mandatory_keys( "TFM/MMPlayer/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows the attacker to execute arbitrary
  code on the system or cause the application to crash." );
	script_tag( name: "affected", value: "TFM MMPlayer version 2.0 to 2.2.0.30 on Windows." );
	script_tag( name: "insight", value: "This flaw is due to improper bounds checking when processing
  '.m3u' files and can be exploited via crafted '.m3u' playlist file containing
  an overly long string." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with TFM MMPlayer and is prone to stack
  based Buffer Overflow bulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35605" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9047" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51442" );
	exit( 0 );
}
require("version_func.inc.sc");
mmplayerVer = get_kb_item( "TFM/MMPlayer/Ver" );
if(mmplayerVer != NULL){
	if(version_in_range( version: mmplayerVer, test_version: "2.0", test_version2: "2.2.0.30" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

