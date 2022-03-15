CPE = "cpe:/a:vmware:player";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809798" );
	script_version( "$Revision: 11977 $" );
	script_cve_id( "CVE-2015-3650" );
	script_bugtraq_id( 75686 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-02-08 16:30:40 +0530 (Wed, 08 Feb 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "VMware Player Invalid DACL Privilege Escalation Vulnerability (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VMware Player
  and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to error in 'vmware-vmx.exe'
  which does not provide a valid DACL pointer during the setup of the
  vprintproxy.exe process." );
	script_tag( name: "impact", value: "Successful exploitation will allow local
  attackers to gain escalated privileges on the host by injecting a thread
  and execute code in the security context of the affected process." );
	script_tag( name: "affected", value: "VMware Player 6.x before 6.0.7
  and 7.x before 7.1.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to VMware Player version
  6.0.7 or 7.1.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1032823" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2015-0005.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_win.sc" );
	script_mandatory_keys( "VMware/Player/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vmwareVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if( IsMatchRegexp( vmwareVer, "^6\\." ) ){
	if(version_is_less( version: vmwareVer, test_version: "6.0.7" )){
		fix = "6.0.7";
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( vmwareVer, "^7\\." )){
		if(version_is_less( version: vmwareVer, test_version: "7.1.1" )){
			fix = "7.1.1";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vmwareVer, fixed_version: fix );
	security_message( data: report );
	exit( 0 );
}

