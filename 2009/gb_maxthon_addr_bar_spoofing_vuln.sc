if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800896" );
	script_version( "$Revision: 11554 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-22 17:11:42 +0200 (Sat, 22 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3006" );
	script_name( "Maxthon Address Bar Spoofing Vulnerability" );
	script_xref( name: "URL", value: "http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_maxthon_detect.sc" );
	script_mandatory_keys( "Maxthon/Ver" );
	script_tag( name: "impact", value: "Successful exploitation lets the attackers to spoof parts of the
address bar and modify page content on a host that a user may consider partly
trusted." );
	script_tag( name: "affected", value: "Maxthon version 2.5.3.80 on Windows." );
	script_tag( name: "insight", value: "Address bar can be spoofed via 'window.open()' with a relative
URI, to show an arbitrary URL on the web site visited by the victim, as
demonstrated by a visit to an attacker-controlled web page, which triggers a
spoofed login form for the site containing that page." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Maxthon Browser and is prone to Address
  Bar Spoofing vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
maxthonVer = get_kb_item( "Maxthon/Ver" );
if(maxthonVer){
	if(version_is_equal( version: maxthonVer, test_version: "2.5.3.80" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

