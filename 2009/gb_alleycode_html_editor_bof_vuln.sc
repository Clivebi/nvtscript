if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801127" );
	script_version( "$Revision: 14332 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 15:22:43 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-10-23 16:18:41 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3708", "CVE-2009-3709" );
	script_name( "Alleycode HTML Editor Buffer Overflow Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36940" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/0910-exploits/alleycode-overflow.txt" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_alleycode_html_editor_detect.sc" );
	script_mandatory_keys( "Alleycode-HTML-Editor/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary
code or compromise a user's system." );
	script_tag( name: "affected", value: "Alleycode HTML Editor version 2.21 and prior" );
	script_tag( name: "insight", value: "Multiple boundary error exists in the Meta Content Optimizer when
displaying the content of 'TITLE' or 'META' HTML tags. This can be exploited to
cause a stack-based buffer overflow via an HTML file defining an overly long
'TITLE' tag, 'description' or 'keywords' 'META' tag." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Alleycode HTML Editor and is prone
to Buffer Overflow vulnerabilities." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
aheVer = get_kb_item( "Alleycode-HTML-Editor/Ver" );
if(!aheVer){
	exit( 0 );
}
if(version_is_less_equal( version: aheVer, test_version: "2.2.1" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

