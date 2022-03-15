CPE = "cpe:/a:symantec:anti-virus_engine";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808534" );
	script_version( "2020-03-04T09:29:37+0000" );
	script_cve_id( "CVE-2016-2208" );
	script_bugtraq_id( 90653 );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-03-04 09:29:37 +0000 (Wed, 04 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-07-04 14:15:06 +0530 (Mon, 04 Jul 2016)" );
	script_name( "Symantec Antivirus Engine Denial of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Symantec
  Antivirus Engine and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error in the
  kernel component via a malformed PE header file." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service." );
	script_tag( name: "affected", value: "Symantec Anti-Virus Engine (AVE) 20151.1
  before 20151.1.1.4." );
	script_tag( name: "solution", value: "Update to Symantec Anti-Virus Engine (AVE)
  version 20151.1.1.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&amp;pvid=security_advisory&amp;suid=20160516_00" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_symantec_antivirus_engine_detect_win.sc" );
	script_mandatory_keys( "Symantec/Antivirus/Engine/Ver" );
	script_xref( name: "URL", value: "https://support.symantec.com/en_US/article.TECH103088.html" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!sepVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: sepVer, test_version: "20151.1.1.4" )){
	report = report_fixed_ver( installed_version: sepVer, fixed_version: "20151.1.1.4" );
	security_message( data: report );
	exit( 0 );
}

