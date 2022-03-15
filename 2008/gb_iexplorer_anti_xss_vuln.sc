if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800208" );
	script_version( "2020-12-08T12:38:13+0000" );
	script_tag( name: "last_modification", value: "2020-12-08 12:38:13 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2008-12-19 13:40:09 +0100 (Fri, 19 Dec 2008)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_bugtraq_id( 32780 );
	script_cve_id( "CVE-2008-5551", "CVE-2008-5552", "CVE-2008-5553", "CVE-2008-5554", "CVE-2008-5555", "CVE-2008-5556" );
	script_name( "Microsoft Internet Explorer Anti-XSS Filter Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/499124" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/0812-exploits/ie80-xss.txt" );
	script_xref( name: "URL", value: "http://www.webappsec.org/lists/websecurity/archive/2008-12/msg00057.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can perform the XSS attacks on the remote hosts without any consent of IE." );
	script_tag( name: "affected", value: "Microsoft Windows Platform with Internet Explorer 8.0 Beta 2." );
	script_tag( name: "insight", value: "These flaws are due to:

  - Injections facilitated by some HTTP headers are not currently blocked.

  - Injections into some contexts are not blocked where contents can be
  injected directly into JavaScript without breaking out a string.

  - Allowing access to the attacker to inject XSS string in 2 different HTML
  positions.

  - It lets the attacker execute XSS attacks using CRLF sequence in
  conjunction with a crafted Content-Type header." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Internet Explorer and is prone to
  anti-xss filter vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
if(!ieVer = get_kb_item( "MS/IE/Version" )){
	exit( 0 );
}
if(version_in_range( version: ieVer, test_version: "8.0", test_version2: "8.0.6001.18241" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

