if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801094" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2009-4129", "CVE-2009-4130" );
	script_bugtraq_id( 37230, 37232 );
	script_name( "Mozilla Firefox Multiple Spoofing Vulnerabilies - dec09 (Linux)" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54612" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54611" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Dec/1023287.html" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_lin.sc" );
	script_mandatory_keys( "Firefox/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to conduct spoofing attacks and
  possibly launch further attacks on the system." );
	script_tag( name: "affected", value: "Mozilla Firefox version 3.0 to 3.5.5 on Linux." );
	script_tag( name: "insight", value: "- A race condition error allows attackers to produce a JavaScript message with
    a spoofed domain association by writing the message in between the document
    request and document load for a web page in a different domain.

  - Visual truncation vulnerability in the MakeScriptDialogTitle function in
    nsGlobalWindow.cpp in Mozilla Firefox allows remote attackers to spoof the
    origin domain name of a script via a long name." );
	script_tag( name: "solution", value: "Upgrade to Firefox version 3.6.3 or later." );
	script_tag( name: "summary", value: "The host is installed with Firefox browser and is prone to multiple
  spoofing vulnerabilies." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "Firefox/Linux/Ver" );
if(!vers){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "3.0", test_version2: "3.5.5" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "3.0 - 3.5.5" );
	security_message( port: 0, data: report );
}

