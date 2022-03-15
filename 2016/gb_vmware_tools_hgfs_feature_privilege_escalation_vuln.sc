CPE = "cpe:/a:vmware:tools";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809031" );
	script_version( "$Revision: 11938 $" );
	script_cve_id( "CVE-2016-5330" );
	script_bugtraq_id( 92323 );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-09-01 10:20:57 +0530 (Thu, 01 Sep 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VMware Tools 'HGFS Feature' Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with
  VMware Tools and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a DLL hijacking
  vulnerability present in the VMware Tools 'Shared Folders' (HGFS) feature
  running on Microsoft Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  local users to gain extra privileges." );
	script_tag( name: "affected", value: "VMware Tools 10.0.5." );
	script_tag( name: "solution", value: "Upgrade to VMware Tools 10.0.6
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0010.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_tools_detect_win.sc" );
	script_mandatory_keys( "VMwareTools/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmtoolVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_equal( version: vmtoolVer, test_version: "10.0.5" )){
	report = report_fixed_ver( installed_version: vmtoolVer, fixed_version: "10.0.6" );
	security_message( data: report );
	exit( 0 );
}

