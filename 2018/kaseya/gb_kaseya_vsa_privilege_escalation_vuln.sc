CPE = "cpe:/a:kaseya:virtual_system_administrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813382" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_cve_id( "CVE-2017-12410" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 20:01:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2018-05-30 11:18:44 +0530 (Wed, 30 May 2018)" );
	script_name( "Kaseya Virtual System Administrator Agent Local Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is running Kaseya Virtual System Administrator agent which
  is prone to a local privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a Time of Check &
  Time of Use (TOCTOU) issue when VSA agent performs verification if the
  files were modified before running the executables." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to run arbitrary executables with 'NT AUTHORITY\\SYSTEM' privileges." );
	script_tag( name: "affected", value: "Kaseya Virtual System Administrator
  agent 9.4.0.36 and earlier." );
	script_tag( name: "solution", value: "Upgrade to Kaseya Virtual System
  Administrator version 9.4.0.37 or 9.5 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/archive/1/archive/1/541884/100/0/threaded" );
	script_xref( name: "URL", value: "https://helpdesk.kaseya.com/hc/en-gb/articles/360002367172-CVE-2017-12410-TOCTOU-Flaw-in-the-VSA-s-Agent-" );
	script_xref( name: "URL", value: "https://www.kaseya.com/products/vsa" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kaseya_vsa_detect.sc" );
	script_mandatory_keys( "kaseya_vsa/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_kb_item( "kaseya_vsa/patchlevel" )){
	if(!version = get_app_version( cpe: CPE, port: port )){
		exit( 0 );
	}
}
if(version_is_less( version: version, test_version: "9.4.0.37" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "9.4.0.37 or 9.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

