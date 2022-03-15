if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900823" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1873", "CVE-2009-1874" );
	script_bugtraq_id( 36047, 36050 );
	script_name( "Adobe JRun Management Console Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_adobe_jrun_detect.sc", "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "/Adobe/JRun/Ver", "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to cause XSS attacks or
  Directory Traversal attack using the affected application." );
	script_tag( name: "affected", value: "Adobe JRun version 4.0 on Windows." );
	script_tag( name: "insight", value: "- Multiple XSS vulnerabilities exist due to error in the Management
  Console which can be exploited to inject arbitrary web script or HTML via unspecified vectors.

  - A Directory traversal attack is possible due to error in logging/logviewer.jsp in the Management Console
  which can be exploited by authenticated users to read arbitrary files via a .. (dot dot) in the logfile parameter." );
	script_tag( name: "summary", value: "The host is running Adobe JRun and is prone to multiple vulnerabilities." );
	script_tag( name: "solution", value: "Apply the security updates from the referenced advisories." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://download.macromedia.com/pub/coldfusion/updates/jmc-app.ear" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36329/" );
	script_xref( name: "URL", value: "http://www.dsecrg.com/pages/vul/show.php?id=151" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb09-12.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("http_func.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
jrunVer = get_kb_item( "/Adobe/JRun/Ver" );
if(IsMatchRegexp( jrunVer, "^4" )){
	if(!get_kb_item( "SMB/WindowsVersion" )){
		exit( 0 );
	}
	jrunFile = registry_get_sz( key: "SOFTWARE\\Macromedia\\Install Data\\JRun 4", item: "INSTALLDIR" );
	jrunFile += "\\bin\\jrun.exe";
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: jrunFile );
	jrun = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: jrunFile );
	jrunVer = GetVer( file: jrun, share: share );
	if(version_in_range( version: jrunVer, test_version: "4.0", test_version2: "4.0.7.43085" )){
		report = report_fixed_ver( installed_version: jrunVer, vulnerable_range: "4.0 - 4.0.7.43085" );
		security_message( port: 0, data: report );
	}
}

