if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900960" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-10-01 12:15:29 +0200 (Thu, 01 Oct 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-3340" );
	script_bugtraq_id( 36235 );
	script_name( "freeSSHd Pre-Authentication Error Remote DoS Vulnerability" );
	script_xref( name: "URL", value: "http://intevydis.com/vd-list.shtml" );
	script_xref( name: "URL", value: "http://www.intevydis.com/blog/?p=57" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36506" );
	script_xref( name: "URL", value: "http://securitytracker.com/alerts/2009/Sep/1022811.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_freesshd_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "freeSSHd/Ver" );
	script_tag( name: "impact", value: "Successful attack could allow attackers to crash application to cause
  denial of service." );
	script_tag( name: "affected", value: "freeSSHd version 1.2.4 and prior." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified pre-authentication error." );
	script_tag( name: "solution", value: "Upgrade to freeSSHd version 1.2.6 or later." );
	script_tag( name: "summary", value: "This host has freeSSHd installed and is prone to Denial of Service
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.freesshd.com/" );
	exit( 0 );
}
require("version_func.inc.sc");
sshdVer = get_kb_item( "freeSSHd/Ver" );
if(sshdVer){
	if(version_is_less_equal( version: sshdVer, test_version: "1.2.4" )){
		report = report_fixed_ver( installed_version: sshdVer, vulnerable_range: "Less than or equal to 1.2.4" );
		security_message( port: 0, data: report );
	}
}

