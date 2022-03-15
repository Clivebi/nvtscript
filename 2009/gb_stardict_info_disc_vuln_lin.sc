if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800644" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-2260" );
	script_name( "StarDict Information Disclosure Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/504583" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=508945" );
	script_xref( name: "URL", value: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534731" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_stardict_detect_lin.sc" );
	script_mandatory_keys( "StarDict/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain sensitive
information by sniffing the network." );
	script_tag( name: "affected", value: "StarDict version 3.0.1 on Linux" );
	script_tag( name: "insight", value: "Error exists when 'enable net dict' is configured, and it
attempts to grab clipboard and sends it over network." );
	script_tag( name: "solution", value: "Upgrade to StarDict 3.0.1-5 or later." );
	script_tag( name: "summary", value: "This host is installed with StarDict and is prone to
Information Disclosure Vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.stardict.org/download.php" );
	exit( 0 );
}
require("version_func.inc.sc");
stardictVer = get_kb_item( "StarDict/Linux/Ver" );
if(!stardictVer){
	exit( 0 );
}
if(stardictVer){
	if(version_is_equal( version: stardictVer, test_version: "3.0.1" )){
		report = report_fixed_ver( installed_version: stardictVer, vulnerable_range: "Equal to 3.0.1" );
		security_message( port: 0, data: report );
	}
}

