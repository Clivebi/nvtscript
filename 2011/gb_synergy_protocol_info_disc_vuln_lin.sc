if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801873" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Synergy Protocol Information Disclosure Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/100157/synergy-cleartext.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_synergy_detect_lin.sc" );
	script_mandatory_keys( "Synergy/Lin/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to obtain sensitive
information that could aid in further attacks." );
	script_tag( name: "affected", value: "Synergy Version 1.4" );
	script_tag( name: "insight", value: "The flaw is caused by sending all keystrokes and mouse movements
in clear text, which allows attacker to eavesdrop on all information passed
between the multiple computers." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Synergy and is prone to information
disclosure vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "Synergy/Lin/Ver" );
if(ver){
	if(version_in_range( version: ver, test_version: "1.4.0", test_version2: "1.4.2" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

