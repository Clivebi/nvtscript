if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901149" );
	script_version( "2021-09-01T09:31:49+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 09:31:49 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)" );
	script_cve_id( "CVE-2010-3132" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Dreamweaver Insecure Library Loading Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/41110" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/14740" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2010/2171" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_dreamweaver_detect.sc" );
	script_mandatory_keys( "Adobe/Dreamweaver/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute
arbitrary code and conduct DLL hijacking attacks." );
	script_tag( name: "affected", value: "Adobe Dreamweaver CS5 11.0" );
	script_tag( name: "insight", value: "This flaw is due to the application insecurely loading certain
libraries from the current working directory, which could allow attackers
to execute arbitrary code by tricking a user into opening a file from a
network share." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Adobe Dreamweaver and is prone to
Insecure Library Loading vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ver = get_kb_item( "Adobe/Dreamweaver/Ver" );
adobeVer = eregmatch( pattern: "^(.+) Adobe Dreamweaver (.*)$", string: ver );
if(!isnull( adobeVer[1] ) && ( ContainsString( adobeVer[2], "CS5" ) )){
	if(version_is_equal( version: adobeVer[1], test_version: "11.0" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

