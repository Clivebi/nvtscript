if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900431" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_bugtraq_id( 33210 );
	script_cve_id( "CVE-2009-0135", "CVE-2009-0136" );
	script_name( "Amarok Player Multiple Vulnerabilities" );
	script_xref( name: "URL", value: "http://amarok.kde.org/de/node/600" );
	script_xref( name: "URL", value: "http://secunia.com/Advisories/33505" );
	script_xref( name: "URL", value: "http://trapkit.de/advisories/TKADV2009-002.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_amarok_detect_lin.sc" );
	script_mandatory_keys( "Amarok/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute malicious arbitrary
  codes or can cause heap overflow in the context of the application." );
	script_tag( name: "affected", value: "Amarok Player version prior to 2.0.1.1 on Linux" );
	script_tag( name: "insight", value: "Multiple flaws are due to integer overflow errors within the
  Audible::Tag::readTag function in src/metadata/audible/audibletag.cpp. This
  can be exploited via specially crafted Audible Audio files with a large nlen
  or vlen Tag value." );
	script_tag( name: "solution", value: "Upgrade to the latest version 2.0.1.1." );
	script_tag( name: "summary", value: "This host is installed with Amarok Player for Linux and is prone
  to Multiple Vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
amarokVer = get_kb_item( "Amarok/Linux/Ver" );
if(!amarokVer){
	exit( 0 );
}
if(version_is_less( version: amarokVer, test_version: "2.0.1.1" )){
	report = report_fixed_ver( installed_version: amarokVer, fixed_version: "2.0.1.1" );
	security_message( port: 0, data: report );
}

