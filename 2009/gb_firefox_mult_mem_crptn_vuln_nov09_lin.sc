if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801133" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-11-02 14:39:30 +0100 (Mon, 02 Nov 2009)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3371", "CVE-2009-3377", "CVE-2009-3378", "CVE-2009-3379", "CVE-2009-3381", "CVE-2009-3383" );
	script_bugtraq_id( 36854, 36872, 36873, 36875, 36870, 36869 );
	script_name( "Mozilla Firefox Multiple Memory Corruption Vulnerabilities Nov-09 (Linux)" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-54.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-63.html" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2009/mfsa2009-64.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attacker to cause Denial of Service or
  memory corrption on the user's system." );
	script_tag( name: "affected", value: "Firefox version 3.5 before 3.5.4 on Linux." );
	script_tag( name: "insight", value: "- An error exists when creating JavaScript web-workers recursively that can
    be exploited to trigger the use of freed memory.

  - An error in the embedded 'liboggz' or 'libvorbis' library that can be
    exploited to cause a crash.

  - An error exists in the 'oggplay_data_handle_theora_frame' function in
    media/liboggplay/src/liboggplay/oggplay_data.c in 'liboggplay' library that
    can be exploited to cause a crash." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.5.4." );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
  memory vorruption vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Linux/Ver" );
if(!ffVer){
	exit( 0 );
}
if(version_in_range( version: ffVer, test_version: "3.5", test_version2: "3.5.3" )){
	report = report_fixed_ver( installed_version: ffVer, vulnerable_range: "3.5 - 3.5.3" );
	security_message( port: 0, data: report );
}

