if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900197" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-29 15:16:47 +0100 (Thu, 29 Jan 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-0263" );
	script_bugtraq_id( 33226 );
	script_name( "Winamp AIFF File Multiple Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://milw0rm.com/exploits/7742" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33478" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_winamp_detect.sc" );
	script_mandatory_keys( "Winamp/Version" );
	script_tag( name: "impact", value: "Attackers may leverage this issue by executing arbitrary codes in the context
  of the affected application and can execute denial of service attacks on the
  application." );
	script_tag( name: "affected", value: "Winamp version 5.541 and prior on Windows" );
	script_tag( name: "insight", value: "Application fails to play a large Common Chunk (COMM) header value in an AIFF
  file and a large invalid value in an MP3 file." );
	script_tag( name: "solution", value: "Upgrade to Winamp version 5.57 or later." );
	script_tag( name: "summary", value: "This host is installed with Winamp and is prone to Buffer Overflow
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.winamp.com" );
	exit( 0 );
}
require("version_func.inc.sc");
winampVer = get_kb_item( "Winamp/Version" );
if(!winampVer){
	exit( 0 );
}
if(version_is_less_equal( version: winampVer, test_version: "5.5.4.2165" )){
	report = report_fixed_ver( installed_version: winampVer, vulnerable_range: "Less than or equal to 5.5.4.2165" );
	security_message( port: 0, data: report );
}

