CPE = "cpe:/a:sun:java_system_web_proxy_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800865" );
	script_version( "$Revision: 12602 $" );
	script_cve_id( "CVE-2009-2597" );
	script_bugtraq_id( 35788 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2009-08-12 19:54:51 +0200 (Wed, 12 Aug 2009)" );
	script_name( "Sun Java System Web Proxy Server Denial Of Service Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host has Java Web Proxy Server running, which is prone to
  Denial of Service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error, which can be exploited to
  cause a crash via a 'GET' request if the Sun Java System Web Proxy Server is
  the used deployment container for the agent." );
	script_tag( name: "impact", value: "Successful exploitation will lets the attackers to cause a Denial of Service.
  in the context of an affected application." );
	script_tag( name: "affected", value: "Sun Java System Access Manager Policy Agent version 2.2
  Sun Java System Web Proxy Server version 4.0.x on Windows." );
	script_tag( name: "solution", value: "Apply patch 141248-01 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod", value: "30" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/35979/" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-66-258508-1" );
	script_xref( name: "URL", value: "http://sunsolve.sun.com/search/document.do?assetkey=1-21-141248-01-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_sun_java_sys_web_proxy_server_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "Sun/JavaWebProxyServ/Installed", "Host/runs_windows" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
sun_port = get_app_port( cpe: CPE );
if(!sun_port){
	exit( 0 );
}
version = get_app_version( cpe: CPE, port: sun_port );
if(!version){
	exit( 0 );
}
if(!ContainsString( version, "4.0" )){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Sun Microsystems\\ProxyServer" )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	agentName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(agentName != NULL && IsMatchRegexp( agentName, "System Access Manager Policy Agent" )){
		agentVer = eregmatch( pattern: "Agents\\/([0-9.]+)", string: agentName );
		if(!isnull( agentVer[1] )){
			if(version_is_equal( version: agentVer[1], test_version: "2.2" )){
				report = report_fixed_ver( installed_version: agentVer[1], fixed_version: "Apply Patch" );
				security_message( port: sun_port, data: report );
				exit( 0 );
			}
		}
	}
}

