if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900395" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-07-29 08:37:44 +0200 (Wed, 29 Jul 2009)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_cve_id( "CVE-2009-2542", "CVE-2009-1692" );
	script_bugtraq_id( 35446 );
	script_name( "Netscape 'select()' Object Denial Of Service Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/9160" );
	script_xref( name: "URL", value: "http://www.g-sec.lu/one-bug-to-rule-them-all.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/504969/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_netscape_detect_lin.sc" );
	script_mandatory_keys( "Netscape/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of
service by exhausting memory." );
	script_tag( name: "affected", value: "Netscape version 6 and 8 on Linux" );
	script_tag( name: "insight", value: "Error occurs while calling the 'select()' method with a large
integer that results in continuous allocation of x+n bytes of memory exhausting
memory after a while." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Netscape browser and is prone to
Denial of Service vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
netscapeVer = get_kb_item( "Netscape/Linux/Ver" );
if(IsMatchRegexp( netscapeVer, "^(6|8)\\..*" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

