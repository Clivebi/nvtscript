if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902401" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)" );
	script_cve_id( "CVE-2011-0609" );
	script_bugtraq_id( 46860 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb11-06.html" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/advisories/apsa11-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service." );
	script_tag( name: "affected", value: "Adobe Flash Player version 10.2.152.33 and prior on Linux." );
	script_tag( name: "insight", value: "The flaw is due to an error when handling the 'SWF' file, which allows
  attackers to execute arbitrary code or cause a denial of service via crafted
  flash content." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player version 10.2.153.1 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  memory corruption vulnerability." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
vers = get_kb_item( "AdobeFlashPlayer/Linux/Ver" );
if(!vers){
	exit( 0 );
}
vers = ereg_replace( pattern: ",", string: vers, replace: "." );
if(version_is_less_equal( version: vers, test_version: "10.2.152.33" )){
	report = report_fixed_ver( installed_version: vers, vulnerable_range: "Less than or equal to 10.2.152.33" );
	security_message( port: 0, data: report );
}

