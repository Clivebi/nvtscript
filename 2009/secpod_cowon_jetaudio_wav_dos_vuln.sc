if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900977" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3948" );
	script_name( "COWON Media Center JetAudio .wav File Denial Of Service Vulnerability" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_cowon_jetaudio_detect.sc" );
	script_mandatory_keys( "JetAudio/Ver" );
	script_tag( name: "summary", value: "This host has COWON Media Center JetAudio installed and is prone
  to Denial of Service vulnerability." );
	script_tag( name: "insight", value: "An error occurs while parsing a .wav file containing an overly long string
  at the end." );
	script_tag( name: "impact", value: "Attackers can exploit this issue to corrupt memory and cause the application
  to crash." );
	script_tag( name: "affected", value: "COWON Media Center JetAudio 7.5.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to COWON Media Center JetAudio version 8.0.6 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9139" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51697" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!version = get_kb_item( "JetAudio/Ver" )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "7.5.3.15" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Equal to 7.5.3.15" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

