if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.101018" );
	script_version( "2021-05-26T11:52:35+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 11:52:35 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2009-04-01 22:29:14 +0200 (Wed, 01 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Microsoft Windows SharePoint Services (WSS) Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Christian Eric Edjenguele" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Microsoft Windows SharePoint Services (WSS).

  Microsoft SharePoint products and technologies include browser-based collaboration and a document-management platform.
  These can be used to host web sites that access shared workspaces and documents from a browser." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
if(!banner = http_get_remote_headers( port: port, file: "/vt-test" + rand() + ".aspx" )){
	exit( 0 );
}
if(!IsMatchRegexp( banner, "MicrosoftSharePointTeamServices\\s*:" )){
	exit( 0 );
}
dotNetServer = eregmatch( pattern: "Server\\s*:\\s*(Microsoft-)?IIS/([0-9.]+)", string: banner, icase: TRUE );
mstsVersion = eregmatch( pattern: "MicrosoftSharePointTeamServices\\s*:\\s*([0-9.]+)", string: banner, icase: TRUE );
xPoweredBy = eregmatch( pattern: "X-Powered-By\\s*:\\s*([a-zA-Z.]+)", string: banner, icase: TRUE );
aspNetVersion = eregmatch( pattern: "X-AspNet-Version\\s*:\\s*([0-9.]+)", string: banner, icase: TRUE );
if(mstsVersion){
	wssVersion = "";
	set_kb_item( name: "WindowsSharePointServices/installed", value: TRUE );
	set_kb_item( name: "MicrosoftSharePointTeamServices/version", value: mstsVersion[1] );
	register_host_detail( name: "App", value: "cpe:/a:microsoft:sharepoint_team_services:2007" );
	if(eregmatch( pattern: "(6.0.2.[0-9]+)", string: mstsVersion[1], icase: TRUE )){
		wssVersion = "2.0";
		set_kb_item( name: "WindowsSharePointServices/version", value: wssVersion );
		register_and_report_cpe( app: "Microsoft Windows SharePoint Services (WSS)", ver: wssVersion, base: "cpe:/a:microsoft:sharepoint_services:", expr: "^([0-9]\\.[0-9])", regPort: port, insloc: "/" );
	}
	if(eregmatch( pattern: "(12.[0-9.]+)", string: mstsVersion[1], icase: TRUE )){
		wssVersion = "3.0";
		set_kb_item( name: "WindowsSharePointServices/version", value: wssVersion );
		register_and_report_cpe( app: "Microsoft Windows SharePoint Services (WSS)", ver: wssVersion, base: "cpe:/a:microsoft:sharepoint_services:", expr: "^([0-9]\\.[0-9])", regPort: port, insloc: "/" );
	}
	report = "Detected:\n - " + mstsVersion[0];
	if(wssVersion){
		report += "\n" + "- Microsoft Windows SharePoint Services (WSS): " + wssVersion;
	}
}
if(dotNetServer){
	osVersion = "";
	if(dotNetServer[2] == "10.0"){
		osVersion = "Windows Server 2016 / Windows 10";
	}
	if(dotNetServer[2] == "8.5"){
		osVersion = "Windows Server 2012 R2 / Windows 8.1";
	}
	if(dotNetServer[2] == "8.0"){
		osVersion = "Windows Server 2012 / Windows 8";
	}
	if(dotNetServer[2] == "7.5"){
		osVersion = "Windows Server 2008 R2 / Windows 7";
	}
	if(dotNetServer[2] == "7.0"){
		osVersion = "Windows Server 2008 / Windows Vista";
	}
	if(dotNetServer[2] == "6.0"){
		osVersion = "Windows Server 2003 / Windows XP Professional x64";
	}
	if(dotNetServer[2] == "5.1"){
		osVersion = "Windows XP Professional";
	}
	if(dotNetServer[2] == "5.0"){
		osVersion = "Windows 2000";
	}
	if(dotNetServer[2] == "4.0"){
		osVersion = "Windows NT 4.0 Option Pack";
	}
	if(dotNetServer[2] == "3.0"){
		osVersion = "Windows NT 4.0 SP2";
	}
	if(dotNetServer[2] == "2.0"){
		osVersion = "Windows NT 4.0";
	}
	if(dotNetServer[2] == "1.0"){
		osVersion = "Windows NT 3.51";
	}
	report += "\n - " + dotNetServer[0];
	if(osVersion){
		report += "\n - Operating System Type: " + osVersion;
	}
}
if(aspNetVersion){
	set_kb_item( name: "aspNetVersion/version", value: aspNetVersion[1] );
	report += "\n - " + aspNetVersion[0];
	if(xPoweredBy){
		set_kb_item( name: "ASPX/enabled", value: TRUE );
		report += "\n - " + xPoweredBy[0];
	}
}
if(strlen( report ) > 0){
	log_message( port: port, data: report );
}
exit( 0 );

