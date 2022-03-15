if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800708" );
	script_version( "2020-04-27T09:00:11+0000" );
	script_tag( name: "last_modification", value: "2020-04-27 09:00:11 +0000 (Mon, 27 Apr 2020)" );
	script_tag( name: "creation_date", value: "2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1574" );
	script_name( "IPSec Tools Denial of Service Vulnerability" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=497990" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/05/04/3" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/04/29/6" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_ipsec-tools_detect.sc" );
	script_mandatory_keys( "IPSec/Tools/Ver" );
	script_tag( name: "affected", value: "IPsec Tools version prior to 0.7.2" );
	script_tag( name: "insight", value: "This flaw is due to a NULL pointer dereference caused when the file
  'racoon/isakmp_frag.c' processes fragmented packets without any payload." );
	script_tag( name: "solution", value: "Upgrade to the latest version 0.7.2." );
	script_tag( name: "summary", value: "This host is installed with IPSec Tools for Linux and is prone
  to Denial of Service Vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will let the attacker cause denial if service." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
ipsecVer = get_kb_item( "IPSec/Tools/Ver" );
if(!ipsecVer){
	exit( 0 );
}
if(version_is_less( version: ipsecVer, test_version: "0.7.2" )){
	report = report_fixed_ver( installed_version: ipsecVer, fixed_version: "0.7.2" );
	security_message( port: 0, data: report );
}

