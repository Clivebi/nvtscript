CPE = "cpe:/a:vmware:workstation";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810535" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_cve_id( "CVE-2016-7081", "CVE-2016-7082", "CVE-2016-7083", "CVE-2016-7084", "CVE-2016-7085", "CVE-2016-7086" );
	script_bugtraq_id( 92935, 92934, 92940, 92941 );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-30 01:29:00 +0000 (Sun, 30 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-02-03 13:26:13 +0530 (Fri, 03 Feb 2017)" );
	script_name( "VMware Workstation Multiple Code Execution Vulnerabilities Feb17 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with VMware Workstation
  and is prone to multiple code execution vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Multiple heap-based buffer overflows via Cortado Thinprint.

  - Multiple memory corruption vulnerabilities via Cortado Thinprint.

  - An untrusted search path vulnerability in the installer.

  - An insecure executable loading vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to execute arbitrary code and do local privilege escalation." );
	script_tag( name: "affected", value: "VMware Workstation 12.x before
  12.5.0 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Workstation version
  12.5.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://www.vmware.com/security/advisories/VMSA-2016-0014.html" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(IsMatchRegexp( vmwareVer, "^12" )){
	if(version_is_less( version: vmwareVer, test_version: "12.5.0" )){
		report = report_fixed_ver( installed_version: vmwareVer, fixed_version: "12.5.0" );
		security_message( data: report );
		exit( 0 );
	}
}

