if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902927" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 55797 );
	script_cve_id( "CVE-2012-2520" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-10-10 10:34:20 +0530 (Wed, 10 Oct 2012)" );
	script_name( "Microsoft Products HTML Sanitisation Component XSS Vulnerability (2741517)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc", "gb_ms_sharepoint_sever_n_foundation_detect.sc", "secpod_office_products_version_900032.sc", "gb_ms_office_web_apps_detect.sc", "secpod_ms_lync_detect_win.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass certain security
  restrictions and conduct cross-site scripting and spoofing attacks." );
	script_tag( name: "affected", value: "- Microsoft Lync 2010

  - Microsoft Lync 2010 Attendee

  - Microsoft Communicator 2007 R2

  - Microsoft InfoPath 2007 Service Pack 2

  - Microsoft InfoPath 2007 Service Pack 3

  - Microsoft InfoPath 2010 Service Pack 1

  - Microsoft Groove Server 2010 Service Pack 1

  - Microsoft Office Web Apps 2010 Service Pack 1

  - Microsoft SharePoint Server 2010 Service Pack 1

  - Microsoft SharePoint Server 2007 Service Pack 2

  - Microsoft SharePoint Server 2007 Service Pack 3

  - Microsoft SharePoint Foundation 2010 Service Pack 1

  - Microsoft Windows SharePoint Services 3.0 Service Pack 2" );
	script_tag( name: "insight", value: "Certain unspecified input is not properly sanitised within the HTML
  Sanitisation component before being returned to the user. This can be
  exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS12-066." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2687439" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2687440" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/117220/sa50855.txt" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-066" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(get_kb_item( "MS/Lync/Ver" )){
	path = get_kb_item( "MS/Lync/path" );
	if(path){
		commVer = fetch_file_version( sysPath: path, file_name: "communicator.exe" );
		if(commVer){
			if(version_in_range( version: commVer, test_version: "3.5", test_version2: "3.5.6907.260" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
if(get_kb_item( "MS/Lync/Attendee/Ver" )){
	path = get_kb_item( "MS/Lync/Attendee/path" );
	if(path){
		oglVer = fetch_file_version( sysPath: path, file_name: "Ogl.dll" );
		if(oglVer){
			if(version_in_range( version: oglVer, test_version: "4.0", test_version2: "4.0.7577.4097" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
keys = make_list( "SOFTWARE\\Microsoft\\Office\\12.0\\InfoPath\\InstallRoot",
	 "SOFTWARE\\Microsoft\\Office\\14.0\\InfoPath\\InstallRoot" );
for key in keys {
	if(registry_key_exists( key: key )){
		infoPath = registry_get_sz( key: key, item: "Path" );
		if(infoPath){
			exeVer = fetch_file_version( sysPath: infoPath, file_name: "Infopath.Exe" );
			dllVer = fetch_file_version( sysPath: infoPath, file_name: "Ipeditor.dll" );
			if(( exeVer && ( version_in_range( version: exeVer, test_version: "12.0", test_version2: "12.0.6662.5003" ) || version_in_range( version: exeVer, test_version: "14.0", test_version2: "14.0.6123.5005" ) ) ) || ( dllVer && ( version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6662.5003" ) || version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6126.4999" ) ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\Office Server\\14.0\\Groove\\Groove Relay";
if(registry_key_exists( key: key )){
	dllPath = registry_get_sz( key: key, item: "RelayCFg" );
	if(dllPath){
		dllPath = dllPath - "RelayCfg.cpl";
		dllVer = fetch_file_version( sysPath: dllPath, file_name: "Groovers.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6123.5004" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
cpe_list = make_list( "cpe:/a:microsoft:sharepoint_server",
	 "cpe:/a:microsoft:sharepoint_foundation",
	 "cpe:/a:microsoft:sharepoint_services",
	 "cpe:/a:microsoft:office_web_apps" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if(ContainsString( cpe, "cpe:/a:microsoft:sharepoint_server" )){
	if( IsMatchRegexp( vers, "^12\\." ) ){
		path = registry_get_sz( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", item: "CommonFilesDir" );
		if(path){
			path = path + "\\Microsoft Shared\\web server extensions\\12\\ISAPI";
			dllVer = fetch_file_version( sysPath: path, file_name: "Microsoft.office.server.dll" );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6650.4999" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
	else {
		if(IsMatchRegexp( vers, "^14\\." )){
			key = "SOFTWARE\\Microsoft\\Office Server\\14.0";
			file = "Microsoft.office.server.native.dll";
		}
	}
	if(key && registry_key_exists( key: key ) && file){
		if(path = registry_get_sz( key: key, item: "BinPath" )){
			dllVer = fetch_file_version( sysPath: path, file_name: file );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6108.4999" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
if(ContainsString( cpe, "cpe:/a:microsoft:sharepoint_foundation" )){
	key = "SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\14.0";
	if(registry_key_exists( key: key )){
		dllPath = registry_get_sz( key: key, item: "Location" );
		if(dllPath){
			dllVer = fetch_file_version( sysPath: dllPath, file_name: "BIN\\Onetutil.dll" );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6123.5005" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
if(ContainsString( cpe, "cpe:/a:microsoft:sharepoint_services" )){
	key = "SOFTWARE\\Microsoft\\Shared Tools";
	if(registry_key_exists( key: key )){
		dllPath = registry_get_sz( key: key, item: "SharedFilesDir" );
		if(dllPath){
			dllVer = fetch_file_version( sysPath: dllPath, file_name: "web server extensions\\12\\BIN\\Onetutil.dll" );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "12.0", test_version2: "12.0.6665.4999" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
if(ContainsString( cpe, "cpe:/a:microsoft:office_web_apps" )){
	if(IsMatchRegexp( vers, "^14\\." )){
		path = get_kb_item( "MS/Office/Web/Apps/Path" );
		if(path && !ContainsString( path, "Could not find the install" )){
			path = path + "\\14.0\\WebServices\\ConversionService\\Bin\\Converter";
			dllVer = fetch_file_version( sysPath: path, file_name: "msoserver.dll" );
			if(dllVer){
				if(version_in_range( version: dllVer, test_version: "14.0", test_version2: "14.0.6123.5000" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

