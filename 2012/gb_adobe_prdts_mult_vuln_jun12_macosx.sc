if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802872" );
	script_version( "2020-08-18T09:42:52+0000" );
	script_cve_id( "CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037", "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040" );
	script_bugtraq_id( 53887 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-18 09:42:52 +0000 (Tue, 18 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-06-20 11:02:16 +0530 (Wed, 20 Jun 2012)" );
	script_name( "Adobe Flash Player Multiple Vulnerabilities June-2012 (Mac OS X)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49388" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027139" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-14.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Flash/Player/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors." );
	script_tag( name: "affected", value: "Adobe Flash Player version before 10.3.183.20 and 11.x through 11.2.202.235
  on Mac OS X." );
	script_tag( name: "insight", value: "Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file." );
	script_tag( name: "solution", value: "Update to Adobe Flash Player version 10.3.183.20 or 11.3.300.257 or later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
flashVer = get_kb_item( "Adobe/Flash/Player/MacOSX/Version" );
if(flashVer){
	if(version_is_less( version: flashVer, test_version: "10.3.183.20" ) || version_in_range( version: flashVer, test_version: "11.0", test_version2: "11.2.202.235" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

