if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802202" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-2382" );
	script_name( "Microsoft Internet Explorer Cookie Hijacking Vulnerability" );
	script_xref( name: "URL", value: "http://www.networkworld.com/community/node/74259" );
	script_xref( name: "URL", value: "http://www.theregister.co.uk/2011/05/25/microsoft_internet_explorer_cookiejacking/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_mandatory_keys( "MS/IE/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to read cookie
files of the victim and impersonate users requests." );
	script_tag( name: "affected", value: "Internet Explorer Version 8 and prior and Version 9 Beta." );
	script_tag( name: "insight", value: "The flaw exists due to the application which does not properly
restrict cross-zone drag-and-drop actions, allows user-assisted remote attackers
to read cookie files via vectors involving an IFRAME element with a SRC
attribute containing a file: URL." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Internet Explorer and is prone to
cookie hijacking vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ieVer = get_kb_item( "MS/IE/Version" );
if(!ieVer){
	exit( 0 );
}
if(version_is_less_equal( version: ieVer, test_version: "8.0.6001.18702" ) || version_is_equal( version: ieVer, test_version: "9.0.7930.16406" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

