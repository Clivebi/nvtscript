if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902702" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "ICQ Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103430/icqcli-xss.txt" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_icq_detect.sc" );
	script_mandatory_keys( "ICQ/Ver" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with ICQ and is prone to cross-site
scripting vulnerability." );
	script_tag( name: "insight", value: "The flaw is due to lack of input validation and output
sanitisation of the profile entries.

Impact
Successful exploitation will allow remote attackers to hijack session IDs of
users and leverage the vulnerability to increase the attack vector to the
underlying software and operating system of the victim.

Impact Level: Application.

Affected Software:
ICQ version 7.5 and prior." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
icqVer = get_kb_item( "ICQ/Ver" );
if(!icqVer){
	exit( 0 );
}
if(version_is_less_equal( version: icqVer, test_version: "7.5.0.5255" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

