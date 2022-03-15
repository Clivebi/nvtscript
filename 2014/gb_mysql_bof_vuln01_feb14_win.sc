if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804082" );
	script_version( "2019-07-05T09:29:25+0000" );
	script_cve_id( "CVE-2014-0001" );
	script_bugtraq_id( 65298 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 09:29:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-02-03 18:02:51 +0530 (Mon, 03 Feb 2014)" );
	script_name( "Oracle MySQL Client Remote Buffer Overflow Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Oracle MySQL Client and is prone to remote buffer
overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to an user-supplied input is not properly validated when handling
server versions in client/mysql.cc." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to manipulate certain data and
cause a DoS (Denial of Service)." );
	script_tag( name: "affected", value: "Oracle MySQL version 5.5.34 and earlier." );
	script_tag( name: "solution", value: "Upgrade to MySQL version 5.5.35 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.scip.ch/en/?vuldb.12135" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1029708" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	appName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( appName, "MySQL Server" )){
		insloc = registry_get_sz( key: key + item, item: "InstallLocation" );
		if(!insloc){
			continue;
		}
		clientVer = fetch_file_version( sysPath: insloc, file_name: "bin\\mysql.exe" );
		if(clientVer && IsMatchRegexp( clientVer, "^(5\\.5)" )){
			if(version_in_range( version: clientVer, test_version: "5.5", test_version2: "5.5.34" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

