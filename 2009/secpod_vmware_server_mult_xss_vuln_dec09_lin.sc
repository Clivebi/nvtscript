if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900899" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-12-21 07:14:17 +0100 (Mon, 21 Dec 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-3731" );
	script_bugtraq_id( 37346 );
	script_name( "VMware Server Multiple Cross-Site Scripting Vulnerabilities (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37460/" );
	script_xref( name: "URL", value: "http://www.webworks.com/Security/2009-0001/" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2009-0017.html" );
	script_xref( name: "URL", value: "http://kb.vmware.com/kb/1016594" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Server/Linux/Ver", "VMware/Linux/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will lets attackers to cause a Denial of Service, or
  compromise a user's system." );
	script_tag( name: "affected", value: "VMware Server version 2.0.2 on Linux." );
	script_tag( name: "insight", value: "- Multiple vulnerabilities can be exploited to disclose sensitive information,
  conduct cross-site scripting attacks, manipulate certain data, bypass certain
  security restrictions, cause a DoS, or compromise a user's system.

  - Certain unspecified input passed to WebWorks help pages is not properly
  sanitised before being returned to the user. This can be exploited to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "summary", value: "The host is installed with VMWare Server that is vulnerable to
  multiple Cross-Site Scripting vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
if(!get_kb_item( "VMware/Linux/Installed" )){
	exit( 0 );
}
vmserVer = get_kb_item( "VMware/Server/Linux/Ver" );
if(vmserVer){
	if(version_is_equal( version: vmserVer, test_version: "2.0.2" )){
		report = report_fixed_ver( installed_version: vmserVer, vulnerable_range: "Equal to 2.0.2" );
		security_message( port: 0, data: report );
	}
}

