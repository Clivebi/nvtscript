if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800811" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1934" );
	script_bugtraq_id( 35204 );
	script_name( "Sun Java System Web Proxy Server Vulnerabilities (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35338" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-21-116648-23-1" );
	script_xref( name: "URL", value: "http://www.sun.com/download/index.jsp" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-259588-1" );
	script_tag( name: "impact", value: "Successful exploitation will lets the attackers to execute arbitrary code,
  gain sensitive information by conducting XSS attacks in the context of an affected site." );
	script_tag( name: "affected", value: "Sun Java System Web Server versions 6.1 and before 6.1 SP11 on Windows." );
	script_tag( name: "insight", value: "The Flaw is due to: error in 'Reverse Proxy Plug-in' which is not properly
  sanitized the input data before being returned to the user. This can be
  exploited to inject arbitrary web script or HTML via the query string in
  situations that result in a 502 Gateway error." );
	script_tag( name: "solution", value: "Update to Web Server version 6.1 SP11." );
	script_tag( name: "summary", value: "This host has Sun Java Web Server running on Windows, which is prone
  to Cross-Site Scripting vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!registry_key_exists( key: "SOFTWARE\\Sun Microsystems\\WebServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	jswsName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(jswsName && IsMatchRegexp( jswsName, "Sun (ONE |Java System )Web Server" )){
		jswsVer = eregmatch( pattern: "Web Server ([0-9.]+)(SP[0-9]+)?", string: jswsName );
		if(!isnull( jswsVer[1] )){
			if( !isnull( jswsVer[2] ) ){
				jswsVer = jswsVer[1] + "." + jswsVer[2];
			}
			else {
				jswsVer = jswsVer[1];
			}
			if(IsMatchRegexp( jswsVer, "^6\\.1" ) && version_in_range( version: jswsVer, test_version: "6.1", test_version2: "6.1.SP10" )){
				report = report_fixed_ver( installed_version: jswsVer, fixed_version: "6.1.SP11" );
				security_message( port: 0, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

