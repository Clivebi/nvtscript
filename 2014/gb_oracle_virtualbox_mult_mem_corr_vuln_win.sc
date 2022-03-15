CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804355" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-0981", "CVE-2014-0983" );
	script_bugtraq_id( 66131, 66133 );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-04-03 15:56:53 +0530 (Thu, 03 Apr 2014)" );
	script_name( "Oracle VM VirtualBox Multiple Memory Corruption Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM VirtualBox and is prone to multiple
memory corruption vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error within the 'crNetRecvReadback' function.

  - Multiple errors within the 'crNetRecvReadback' and 'crNetRecvWriteback'
  functions.

  - A boundary error within multiple generated 'crServerDispatchVertexAttrib*ARB'
  functions." );
	script_tag( name: "impact", value: "Successful exploitation will allow local users to conduct a denial of service
or potentially execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle VM VirtualBox version 4.2.x through 4.2.20, 4.3.x before 4.3.8 on
Windows." );
	script_tag( name: "solution", value: "Upgrade to Oracle VM VirtualBox version 4.3.8 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57384" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/32208" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125660" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_sun_virtualbox_detect_win.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/Win/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^(4\\.(2|3))" )){
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.20" ) || version_in_range( version: virtualVer, test_version: "4.3.0", test_version2: "4.3.7" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

