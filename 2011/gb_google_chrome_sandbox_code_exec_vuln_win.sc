if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801789" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)" );
	script_cve_id( "CVE-2011-2075" );
	script_bugtraq_id( 47771 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Google Chrome 'Sandbox' Remote Code Execution Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://www.youtube.com/watch?v=c8cQ0yU89sk" );
	script_xref( name: "URL", value: "http://www.vupen.com/demos/VUPEN_Pwning_Chrome.php" );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to execute arbitrary
code in the context of the user running the application. Failed attacks may
cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Google Chrome version 11.0.696.65 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an error in application, which bypasses all
security features including 'ASLR/DEP/Sandbox'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed Google Chrome and is prone to remote code
execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "11.0.696.65" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}
exit( 99 );

