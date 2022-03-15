if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803093" );
	script_version( "$Revision: 11401 $" );
	script_cve_id( "CVE-2012-6270", "CVE-2012-6271" );
	script_bugtraq_id( 56975, 56972 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-01-02 15:03:25 +0530 (Wed, 02 Jan 2013)" );
	script_name( "Adobe Shockwave Player Multiple Vulnerabilities Jan-2013 (Mac OS X)" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/546769" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/519137" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027903" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1027905" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80712" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80713" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_shockwave_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Shockwave/MacOSX/Version" );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker to execute
  arbitrary code by tricking a user into visiting a specially crafted document." );
	script_tag( name: "affected", value: "Adobe Shockwave Player Versions 11.6.8.638 and prior on
  Mac OS X" );
	script_tag( name: "insight", value: "- An error in Xtras allows attackers to trigger installation of
  arbitrary signed Xtras via a Shockwave movie that contains an Xtra URL.

  - An error exists when handling a specially crafted HTML document that calls
  Shockwave content via a compatibility parameter forcing application to
  downgrade to the insecure version." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with Adobe Shockwave Player and is prone
  to multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("version_func.inc.sc");
shockVer = get_kb_item( "Adobe/Shockwave/MacOSX/Version" );
if(!shockVer){
	exit( 0 );
}
if(version_is_less_equal( version: shockVer, test_version: "11.6.8.638" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

