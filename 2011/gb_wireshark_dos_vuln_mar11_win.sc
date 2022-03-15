if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801758" );
	script_version( "$Revision: 11552 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 15:45:08 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)" );
	script_cve_id( "CVE-2011-1142" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "Wireshark Denial of Service Vulnerability March-11 (Windows)" );
	script_xref( name: "URL", value: "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=1516" );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_dependencies( "gb_wireshark_detect_win.sc" );
	script_mandatory_keys( "Wireshark/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause a
denial of service via vectors involving self-referential ASN.1 CHOICE values." );
	script_tag( name: "affected", value: "Wireshark version 1.2.0 through 1.2.15 Wireshark version 1.4.0
through 1.4.4" );
	script_tag( name: "insight", value: "The flaw is due to stack consumption vulnerability in the
'dissect_ber_choice function' in the 'BER dissector'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Wireshark and is prone to DoS
vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
wiresharkVer = get_kb_item( "Wireshark/Win/Ver" );
if(!wiresharkVer){
	exit( 0 );
}
if(version_in_range( version: wiresharkVer, test_version: "1.2.0", test_version2: "1.2.15" ) || version_in_range( version: wiresharkVer, test_version: "1.4.0", test_version2: "1.4.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

