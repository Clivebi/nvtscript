if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800632" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-1957", "CVE-2009-1958" );
	script_bugtraq_id( 35178 );
	script_name( "strongSwan IKE_SA_INIT and IKE_AUTH DoS Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/1476" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/06/06/9" );
	script_xref( name: "URL", value: "https://lists.strongswan.org/pipermail/users/2009-May/003457.html" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_strongswan_detect.sc" );
	script_mandatory_keys( "StrongSwan/Ver" );
	script_tag( name: "impact", value: "Successful exploit allows attackers to run arbitrary code, corrupt memory,
  and can cause denial of service." );
	script_tag( name: "affected", value: "strongSwan Version prior to 4.2.15 and 4.3.1" );
	script_tag( name: "insight", value: "The flaws are due to:

  - An error in charon/sa/ike_sa.c charon daemon which results in NULL pointer
    dereference and crash via an invalid 'IKE_SA_INIT' request that triggers
   'an incomplete state, ' followed by a 'CREATE_CHILD_SA' request.

  - An error in incharon/sa/tasks/child_create.c charon daemon, it switches
    the NULL checks for TSi and TSr payloads, via an 'IKE_AUTH' request without
    a 'TSi' or 'TSr' traffic selector." );
	script_tag( name: "summary", value: "This host has installed strongSwan and is prone to Denial of Service
  Vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to version 4.3.1, 4.2.15 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
strongswanVer = get_kb_item( "StrongSwan/Ver" );
if(!strongswanVer){
	exit( 0 );
}
if(version_in_range( version: strongswanVer, test_version: "4.1.0", test_version2: "4.2.14" ) || version_is_equal( version: strongswanVer, test_version: "4.3.0" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

