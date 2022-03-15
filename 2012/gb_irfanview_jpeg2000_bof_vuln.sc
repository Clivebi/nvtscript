if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802576" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-0897" );
	script_bugtraq_id( 51426 );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-02-01 11:28:20 +0530 (Wed, 01 Feb 2012)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "IrfanView JPEG-2000 Plugin Remote Stack Based Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/47360" );
	script_xref( name: "URL", value: "http://www.irfanview.com/plugins.htm" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/72398" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "secpod_irfanview_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "IrfanView/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "IrfanView JPEG-2000 Plugin version prior to 4.33" );
	script_tag( name: "insight", value: "The flaw is due to an error in the JPEG2000 plug-in when processing
  the Quantization Default (QCD) marker segment. This can be exploited to cause
  a stack-based buffer overflow via a specially crafted JPEG2000 (JP2) file." );
	script_tag( name: "solution", value: "Upgrade IrfanView JPEG-2000 Plugin version to 4.33 or later." );
	script_tag( name: "summary", value: "This host has IrfanView with JPEG-2000 plugin installed and is
  prone to stack based buffer overflow vulnerability." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
irViewVer = get_kb_item( "IrfanView/Ver" );
if(isnull( irViewVer )){
	exit( 0 );
}
path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\IrfanView", item: "UninstallString" );
if(path != NULL){
	irViewPath = path - "\\iv_uninstall.exe" + "\\Plugins\\JPEG2000.dll";
	plgVer = GetVersionFromFile( file: irViewPath, verstr: "prod" );
	if(!plgVer){
		exit( 0 );
	}
	if(version_is_less( version: plgVer, test_version: "4.33" )){
		report = report_fixed_ver( installed_version: plgVer, fixed_version: "4.33", install_path: irViewPath );
		security_message( port: 0, data: report );
	}
}

