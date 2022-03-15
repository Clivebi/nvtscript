if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801912" );
	script_version( "2020-08-24T11:37:53+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 11:37:53 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)" );
	script_cve_id( "CVE-2011-1126" );
	script_bugtraq_id( 47094 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "VMware Workstation 'vmrun' Library Path Privilege Escalation Vulnerability (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_vmware_prdts_detect_lin.sc" );
	script_mandatory_keys( "VMware/Linux/Installed" );
	script_xref( name: "URL", value: "http://securitytracker.com/id?1025270" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2011-0006.html" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary code with
  elevated privileges, which may aid in other attacks." );
	script_tag( name: "affected", value: "VMware Workstation 6.5.x and 7.x before 7.1.4 build 385536." );
	script_tag( name: "insight", value: "The flaw is caused by an error in the 'vmrun' utility when handling library
  paths, which could be exploited to execute arbitrary code by tricking a user
  into running a vulnerable utility in a directory containing a specially crafted file." );
	script_tag( name: "summary", value: "The host is installed with VMWare Workstation local privilege
  escalation vulnerability." );
	script_tag( name: "solution", value: "Apply the patch or update to Workstation 7.1.4 build 385536." );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:vmware:workstation";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "6.5", test_version2: "6.5.5" ) || version_in_range( version: version, test_version: "7.0", test_version2: "7.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.1.4" );
	security_message( data: report, port: 0 );
	exit( 0 );
}
exit( 99 );

