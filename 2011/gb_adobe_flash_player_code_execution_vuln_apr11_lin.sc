if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801922" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)" );
	script_cve_id( "CVE-2011-0611" );
	script_bugtraq_id( 47314 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Arbitrary Code Execution Vulnerability (Linux)" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/230057" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa11-02.html" );
	script_xref( name: "URL", value: "http://blogs.adobe.com/psirt/2011/04/security-advisory-for-adobe-flash-player-adobe-reader-and-acrobat-apsa11-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to corrupt memory
and execute arbitrary code on the system with elevated privileges." );
	script_tag( name: "affected", value: "Adobe Flash Player version 10.2.153.1 and prior on Linux" );
	script_tag( name: "insight", value: "The flaw is due to an error in handling 'SWF' file in adobe flash
player, which allows attackers to execute arbitrary code or cause a denial
of service via crafted flash content." );
	script_tag( name: "solution", value: "Upgrade adobe flash player to version 10.2.159.1 or later,
Update Adobe Reader/Acrobat to version 9.4.4 or 10.0.3 or later." );
	script_tag( name: "summary", value: "This host has Adobe flash Player installed, and is prone to code
execution vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
flashVer = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
flashVer = ereg_replace( pattern: ",", string: flashVer, replace: "." );
if(flashVer){
	if(version_is_less_equal( version: flashVer, test_version: "10.2.153.1" )){
		report = report_fixed_ver( installed_version: flashVer, vulnerable_range: "Less than or equal to 10.2.153.1" );
		security_message( port: 0, data: report );
	}
}

