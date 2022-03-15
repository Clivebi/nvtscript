if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801273" );
	script_version( "$Revision: 12690 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-06 15:56:20 +0100 (Thu, 06 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)" );
	script_cve_id( "CVE-2010-3134" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Google Earth Insecure Library Loading Vulnerability" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14790/" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_earth_detect.sc" );
	script_mandatory_keys( "Google/Earth/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Google Earth Version 5.1.3535.3218" );
	script_tag( name: "insight", value: "This flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a file from a
network share." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Google Earth and is prone to
insecure library loading vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
geVer = get_kb_item( "Google/Earth/Ver" );
if(geVer != NULL){
	if(version_is_equal( version: geVer, test_version: "5.1.3535.3218" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

