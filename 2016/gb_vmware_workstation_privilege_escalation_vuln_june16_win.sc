CPE = "cpe:/a:vmware:workstation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808109" );
	script_version( "$Revision: 12313 $" );
	script_cve_id( "CVE-2016-2077" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-03 17:28:34 +0530 (Fri, 03 Jun 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VMware Workstation Privilege Escalation vulnerability June16 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with
  VMware Workstation and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to incorrectly accessing
  an executable file." );
	script_tag( name: "impact", value: "Successful exploitation will allow host
  OS users to gain host OS privileges." );
	script_tag( name: "affected", value: "VMware Workstation version 11.x before
  11.1.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to VMware Workstation version
  11.1.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0005.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vmwareVer, "^11\\." )){
	if(version_is_less( version: vmwareVer, test_version: "11.1.3" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "11.1.3" );
		security_message( data: report );
		exit( 0 );
	}
}

