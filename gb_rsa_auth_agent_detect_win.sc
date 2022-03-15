if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803748" );
	script_version( "$Revision: 11279 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2013-08-28 10:27:23 +0530 (Wed, 28 Aug 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "RSA Authentication Agent Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of RSA Authentication Agent.

The script logs in via smb, searches for RSA Authentication Agent and gets
the version from 'DisplayVersion' string in registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\RSA\\RSA Authentication Agent" )){
	if(!registry_key_exists( key: "SOFTWARE\\RSAACEAgents\\Web" )){
		exit( 0 );
	}
}
key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
if(isnull( key_list )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		rsaName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( rsaName, "RSA Authentication Agent" )){
			insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insloc){
				insloc = "Could not find the install location from registry";
			}
		}
		rsaVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(!rsaVer){
			continue;
		}
		if(ContainsString( rsaName, "RSA Authentication Agent" ) && !ContainsString( rsaName, "Web for IIS" ) && registry_key_exists( key: "SOFTWARE\\RSA\\RSA Authentication Agent" )){
			set_kb_item( name: "RSA/AuthenticationAgent6432/Installed", value: rsaVer );
			set_kb_item( name: "RSA/AuthenticationAgent/Ver", value: rsaVer );
			register_and_report_cpe( app: "RSA Authentication Agent", ver: rsaVer, concluded: rsaVer, base: "cpe:/a:emc:rsa_authentication_agent:", expr: "^([0-9.]+)", insloc: insloc );
			if(ContainsString( os_arch, "x64" )){
				set_kb_item( name: "RSA/AuthenticationAgent64/Ver", value: rsaVer );
				register_and_report_cpe( app: "RSA Authentication Agent", ver: rsaVer, concluded: rsaVer, base: "cpe:/a:emc:rsa_authentication_agent:x64:", expr: "^([0-9.]+)", insloc: insloc );
			}
			continue;
		}
		if(ContainsString( rsaName, "RSA Authentication Agent for Web for IIS" ) && registry_key_exists( key: "SOFTWARE\\RSAACEAgents\\Web" )){
			set_kb_item( name: "RSA/AuthenticationAgentWebIIS6432/Installed", value: TRUE );
			set_kb_item( name: "RSA/AuthenticationAgentWebIIS/Ver", value: rsaVer );
			register_and_report_cpe( app: "RSA Authentication Agent", ver: rsaVer, concluded: rsaVer, base: "cpe:/a:emc:rsa_authentication_agent_iis:", expr: "^([0-9.]+)", insloc: insloc );
			if(ContainsString( os_arch, "x64" )){
				set_kb_item( name: "RSA/AuthenticationAgentWebIIS64/Ver", value: rsaVer );
				register_and_report_cpe( app: "RSA Authentication Agent", ver: rsaVer, concluded: rsaVer, base: "cpe:/a:emc:rsa_authentication_agent_iis:x64:", expr: "^([0-9.]+)", insloc: insloc );
			}
		}
	}
}

