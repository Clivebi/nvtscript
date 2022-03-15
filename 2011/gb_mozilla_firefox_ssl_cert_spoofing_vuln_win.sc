if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802100" );
	script_version( "$Revision: 11997 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)" );
	script_cve_id( "CVE-2011-0082" );
	script_bugtraq_id( 48064 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Mozilla Firefox SSL Certificate Spoofing Vulnerability (Windows)" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=709165" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=627552" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to perform
phishing-style attacks by bypassing security warnings when invalid certificates
are used in SSL HTTP connections." );
	script_tag( name: "affected", value: "Mozilla Firefox versions 4.0.x through 4.0.1" );
	script_tag( name: "insight", value: "The flaw is due to improper handling of validation/revalidation of
'SSL' certificates. When re-loading the browser and visiting the page, the
untrusted connection warning would appear, but incorrectly indicates that the
site provides a valid, verified certificate and there is no way to confirm the
exception." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "The host is installed with Mozilla Firefox and is prone to SSL
certificate spoofing vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ffVer = get_kb_item( "Firefox/Win/Ver" );
if(ffVer){
	if(version_in_range( version: ffVer, test_version: "4.0", test_version2: "4.0.1" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

