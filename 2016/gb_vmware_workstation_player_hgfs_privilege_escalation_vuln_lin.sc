CPE = "cpe:/a:vmware:player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809023" );
	script_version( "$Revision: 12051 $" );
	script_cve_id( "CVE-2016-5330" );
	script_bugtraq_id( 92323 );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-01 10:20:57 +0530 (Thu, 01 Sep 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "VMware Workstation Player 'HGFS' Feature Privilege Escalation Vulnerability (Linux)" );
	script_tag( name: "summary", value: "The host is installed with
  VMware Workstation Player and is prone to an important guest privilege
  escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a DLL hijacking
  vulnerability present in the VMware Tools 'Shared Folders' (HGFS) feature
  running on Microsoft Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  local users to gain extra privileges." );
	script_tag( name: "affected", value: "VMware Workstation Player 12.1.x before
  12.1.1 on Linux." );
	script_tag( name: "solution", value: "Upgrade to VMware Workstation Player
  version 12.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmwareVer, "^(12\\.1)" )){
	if(version_is_less( version: vmwareVer, test_version: "12.1.1" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "12.1.1" );
		security_message( data: report );
		exit( 0 );
	}
}

