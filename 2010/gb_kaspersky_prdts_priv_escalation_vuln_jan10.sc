if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800979" );
	script_version( "2020-04-23T12:22:09+0000" );
	script_tag( name: "last_modification", value: "2020-04-23 12:22:09 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-4452" );
	script_bugtraq_id( 37354 );
	script_name( "Kaspersky Products Privilege Escalation Vulnerability" );
	script_xref( name: "URL", value: "http://www.kaspersky.com/productupdates" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37398" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3573" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/508508/100/0/threaded" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_kaspersky_av_detect.sc" );
	script_mandatory_keys( "Kaspersky/products/installed" );
	script_tag( name: "impact", value: "Local attackers can exploit this issue to replace some files (.kdl files)
  by malicious file (corrupted .dll files) and execute arbitrary code with
  SYSTEM privileges." );
	script_tag( name: "affected", value: "Kaspersky Anti-Virus 7, 2009, 2009 prior to 9.0.0.736
  Kaspersky Internet Security 7, 2009, 2009 prior to 9.0.0.736
  Kaspersky Anti-Virus 5.0, 6.0 for Windows Workstations prior to 6.0.4.1212
  Kaspersky Anti-Virus 6.0 for Windows File Servers prior to 6.0.4.1212" );
	script_tag( name: "insight", value: "This flaw occurs due to insecure permissions (Everyone/Full Control)
  applied on the BASES folder which contains configuration files,
  antivirus bases and executable modules." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Upgrade to latest version of appropriate product,
  Kaspersky Anti-Virus/Internet Security 2009 (9.0.0.736)
  Kaspersky Anti-Virus for Windows Workstations/File Servers 6.0 (6.0.4.1212)" );
	script_tag( name: "summary", value: "This host is installed with Kaspersky Products and is prone
  to Privilege Escalation vulnerability." );
	exit( 0 );
}
require("version_func.inc.sc");
kavVer = get_kb_item( "Kaspersky/AV/Ver" );
if(kavVer != NULL){
	if(version_is_less( version: kavVer, test_version: "9.0.0.736" )){
		report = report_fixed_ver( installed_version: kavVer, fixed_version: "9.0.0.736" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
kisVer = get_kb_item( "Kaspersky/IntNetSec/Ver" );
if(kisVer != NULL){
	if(version_is_less( version: kisVer, test_version: "9.0.0.736" )){
		report = report_fixed_ver( installed_version: kisVer, fixed_version: "9.0.0.736" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
kavwVer = get_kb_item( "Kaspersky/AV-Workstation/Ver" );
if(kavwVer != NULL){
	if(version_is_less( version: kavwVer, test_version: "6.0.4.1212" )){
		report = report_fixed_ver( installed_version: kavwVer, fixed_version: "6.0.4.1212" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
kavfsVer = get_kb_item( "Kaspersky/AV-FileServer/Ver" );
if(kavfsVer != NULL){
	if(version_is_less( version: kavfsVer, test_version: "6.0.4.1212" )){
		report = report_fixed_ver( installed_version: kavfsVer, fixed_version: "6.0.4.1212" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}

