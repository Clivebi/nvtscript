if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802557" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_cve_id( "CVE-2011-2713" );
	script_bugtraq_id( 49969 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-01-10 16:22:59 +0530 (Tue, 10 Jan 2012)" );
	script_name( "LibreOffice 'DOC' File Denial of Service Vulnerability (Windows)" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2011/Oct/21" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?102615" );
	script_xref( name: "URL", value: "http://www.libreoffice.org/advisories/CVE-2011-2713/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_libreoffice_detect_portable_win.sc" );
	script_mandatory_keys( "LibreOffice/Win/Ver" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'OpenOffice.org'. A remote user can create
  a specially crafted Word document that, when loaded by the target user, will
  trigger an out-of-bounds read and potentially execute arbitrary code on the
  target system." );
	script_tag( name: "solution", value: "Upgrade to LibreOffice version 3.4.3 or later." );
	script_tag( name: "summary", value: "This host is installed with LibreOffice and is prone to denial of
  service vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target system or cause denial of service." );
	script_tag( name: "affected", value: "LibreOffice version 3.3.0 and 3.4.0 through 3.4.2" );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
officeVer = get_kb_item( "LibreOffice/Win/Ver" );
if(!officeVer){
	exit( 0 );
}
if(IsMatchRegexp( officeVer, "^3\\..*" )){
	if(version_is_less( version: officeVer, test_version: "3.4.3" )){
		report = report_fixed_ver( installed_version: officeVer, fixed_version: "3.4.3" );
	}
	security_message( port: 0, data: report );
}

