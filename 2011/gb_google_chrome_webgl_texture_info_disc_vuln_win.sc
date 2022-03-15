if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802303" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)" );
	script_cve_id( "CVE-2011-2599" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_name( "Google Chrome WebGL Texture Information Disclosure Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://security-tracker.debian.org/tracker/CVE-2011-2599" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain
sensitive information." );
	script_tag( name: "affected", value: "Google Chrome version 11 on windows." );
	script_tag( name: "insight", value: "The flaw is present in the application, which does not block use
of a cross-domain image as a WebGL texture." );
	script_tag( name: "solution", value: "Apply the update from vendor." );
	script_tag( name: "summary", value: "This host is installed with Google Chrome and is prone to
information disclosure vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
chromeVer = get_kb_item( "GoogleChrome/Win/Ver" );
if(!chromeVer){
	exit( 0 );
}
if(IsMatchRegexp( chromeVer, "^11\\." )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

