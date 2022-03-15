CPE = "cpe:/a:adobe:animate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809769" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-7866" );
	script_bugtraq_id( 94872 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:00:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-12-19 18:47:54 +0530 (Mon, 19 Dec 2016)" );
	script_name( "Adobe Animate Memory Corruption Vulnerability-(Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Animate
  and is prone to memory corruption vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when creating '.FLA' files
  with ActionScript Classes that use overly long Class names. This causes memory
  corruption leading to possible arbitrary code execution upon opening a maliciously
  created '.Fla' Flash file." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to
  run arbitrary code execution or conduct a denial of service condition." );
	script_tag( name: "affected", value: "Adobe Animate version 15.2.1.95 and earlier
  on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Animate 16.0.0.112 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2016/Dec/45" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/animate/apsb16-38.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/539923/100/0/threaded" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/140164/Adobe-Animate-15.2.1.95-Buffer-Overflow.html" );
	script_xref( name: "URL", value: "http://hyp3rlinx.altervista.org/advisories/ADOBE-ANIMATE-MEMORY-CORRUPTION-VULNERABILITY.txt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_animate_detect_win.sc" );
	script_mandatory_keys( "Adobe/Animate/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!adVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: adVer, test_version: "16.0.0.112" )){
	report = report_fixed_ver( installed_version: adVer, fixed_version: "16.0.0.112" );
	security_message( data: report );
	exit( 0 );
}

