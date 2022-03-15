if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900676" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-24 07:17:25 +0200 (Wed, 24 Jun 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-1390" );
	script_bugtraq_id( 35288 );
	script_name( "Mutt Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/51068" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/06/10/2" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=504979" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_mutt_detect.sc" );
	script_mandatory_keys( "Mutt/Ver" );
	script_tag( name: "impact", value: "Successful exploits allow attackers to spoof SSL certificates of trusted
  servers and redirect a user to a malicious web site." );
	script_tag( name: "affected", value: "Mutt version 1.5.19 on Linux." );
	script_tag( name: "insight", value: "When Mutt is linked with OpenSSL or GnuTLS it allows connections
  only one TLS certificate in the chain instead of verifying the entire chain." );
	script_tag( name: "solution", value: "Apply the patch from the references." );
	script_tag( name: "summary", value: "This host has installed Mutt and is prone to Security Bypass
  Vulnerability" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
muttVer = get_kb_item( "Mutt/Ver" );
if(!muttVer){
	exit( 0 );
}
if(version_is_equal( version: muttVer, test_version: "1.5.19" )){
	report = report_fixed_ver( installed_version: muttVer, vulnerable_range: "Equal to 1.5.19" );
	security_message( port: 0, data: report );
}

