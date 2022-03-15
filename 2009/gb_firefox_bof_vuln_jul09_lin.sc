if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800847" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-07-18 09:37:41 +0200 (Sat, 18 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2478", "CVE-2009-2479" );
	script_bugtraq_id( 35707 );
	script_name( "Mozilla Firefox Buffer Overflow Vulnerability - July09 (Linux)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9158" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51729" );
	script_xref( name: "URL", value: "https://bugzilla.mozilla.org/show_bug.cgi?id=503286" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful attacks will let attackers to can cause Denial of Service to the
  legitimate user." );
	script_tag( name: "affected", value: "Firefox version 3.5.1 and prior on Linux" );
	script_tag( name: "insight", value: "- A NULL pointer dereference error exists due an unspecified vectors, related
    to a 'flash bug.' which can cause application crash.

  - Stack-based buffer overflow error is caused by sending an overly long string
    argument to the 'document.write' method." );
	script_tag( name: "solution", value: "Upgrade to  Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox browser and is prone
  to Buffer Overflow vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Linux/Ver" );
if(!vers){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "3.5.1" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 3.5.1" );
	security_message( port: 0, data: report );
}

