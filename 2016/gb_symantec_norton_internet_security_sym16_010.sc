CPE = "cpe:/a:symantec:norton_internet_security";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808512" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_cve_id( "CVE-2016-2207", "CVE-2016-2209", "CVE-2016-2210", "CVE-2016-2211", "CVE-2016-3644", "CVE-2016-3645", "CVE-2016-3646" );
	script_bugtraq_id( 91434, 91436, 91437, 91438, 91431, 91439, 91435 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-11 19:23:00 +0000 (Mon, 11 May 2020)" );
	script_tag( name: "creation_date", value: "2016-07-04 16:11:01 +0530 (Mon, 04 Jul 2016)" );
	script_name( "Symantec Norton Internet Security Decomposer Engine Multiple Parsing Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Symantec
  Norton Internet Security and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to an error in
  Parsing of maliciously-formatted container files in Symantecs Decomposer engine." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to cause memory corruption, integer overflow or buffer overflow results in an
  application-level denial of service." );
	script_tag( name: "affected", value: "Symantec Norton Internet Security NGC 22.7 and prior." );
	script_tag( name: "solution", value: "Update Symantec Norton Internet Security
  through LiveUpdate." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160628_00" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "secpod_symantec_prdts_detect.sc" );
	script_mandatory_keys( "Norton/InetSec/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sepVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: sepVer, test_version: "22.7.0.76" )){
	report = report_fixed_ver( installed_version: sepVer, fixed_version: "22.7.0.76" );
	security_message( data: report );
	exit( 0 );
}

