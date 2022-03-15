if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107303" );
	script_version( "2021-09-28T14:11:03+0000" );
	script_tag( name: "last_modification", value: "2021-09-28 14:11:03 +0000 (Tue, 28 Sep 2021)" );
	script_tag( name: "creation_date", value: "2018-03-23 08:14:54 +0100 (Fri, 23 Mar 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-29 17:15:00 +0000 (Wed, 29 Nov 2017)" );
	script_name( "Microsoft Windows Unquoted Path Vulnerability (SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_registry_access.sc", "gb_wmi_access.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB_or_WMI/access_successful" );
	script_cve_id( "CVE-2005-2936", "CVE-2007-5618", "CVE-2009-2761", "CVE-2012-4350", "CVE-2013-0513", "CVE-2013-1092", "CVE-2013-1609", "CVE-2013-1610", "CVE-2013-2151", "CVE-2013-2152", "CVE-2013-2176", "CVE-2013-2231", "CVE-2013-5011", "CVE-2013-6182", "CVE-2013-6773", "CVE-2014-0759", "CVE-2014-4634", "CVE-2014-5455", "CVE-2014-9646", "CVE-2015-0884", "CVE-2015-1484", "CVE-2015-2789", "CVE-2015-3987", "CVE-2015-4173", "CVE-2015-7866", "CVE-2015-8156", "CVE-2015-8988", "CVE-2016-3161", "CVE-2016-4158", "CVE-2016-5793", "CVE-2016-5852", "CVE-2016-6803", "CVE-2016-6935", "CVE-2016-7165", "CVE-2016-8102", "CVE-2016-8225", "CVE-2016-8769", "CVE-2016-9356", "CVE-2017-1000475", "CVE-2017-12730", "CVE-2017-14019", "CVE-2017-14030", "CVE-2017-15383", "CVE-2017-3005", "CVE-2017-3141", "CVE-2017-3751", "CVE-2017-3756", "CVE-2017-3757", "CVE-2017-5873", "CVE-2017-6005", "CVE-2017-7180", "CVE-2017-9247", "CVE-2017-9644", "CVE-2018-0594", "CVE-2018-0595", "CVE-2018-11063", "CVE-2018-20341", "CVE-2018-2406", "CVE-2018-3668", "CVE-2018-3683", "CVE-2018-3684", "CVE-2018-3687", "CVE-2018-3688", "CVE-2018-5470", "CVE-2018-6016", "CVE-2018-6321", "CVE-2018-6384", "CVE-2019-11093", "CVE-2019-14599", "CVE-2019-14685", "CVE-2019-17658", "CVE-2019-20362", "CVE-2019-7201", "CVE-2019-7590", "CVE-2020-0507", "CVE-2020-0546", "CVE-2020-13884", "CVE-2020-15261", "CVE-2020-22809", "CVE-2020-28209", "CVE-2020-35152", "CVE-2020-5147", "CVE-2020-5569", "CVE-2020-7252", "CVE-2020-7316", "CVE-2020-7331", "CVE-2020-8326", "CVE-2020-9292", "CVE-2021-0112", "CVE-2021-21078", "CVE-2021-23879", "CVE-2021-27608", "CVE-2021-35469" );
	script_xref( name: "URL", value: "https://gallery.technet.microsoft.com/scriptcenter/Windows-Unquoted-Service-190f0341#content" );
	script_xref( name: "URL", value: "http://www.ryanandjeffshow.com/blog/2013/04/11/powershell-fixing-unquoted-service-paths-complete/" );
	script_xref( name: "URL", value: "https://www.tecklyfe.com/remediation-microsoft-windows-unquoted-service-path-enumeration-vulnerability/" );
	script_xref( name: "URL", value: "https://blogs.technet.microsoft.com/srd/2018/04/04/triaging-a-dll-planting-vulnerability" );
	script_tag( name: "summary", value: "The script tries to detect Windows 'Uninstall' registry entries
  and 'Services' using an unquoted path containing at least one whitespace." );
	script_tag( name: "insight", value: "If the path contains spaces and is not surrounded by quotation
  marks, the Windows API has to guess where to find the referenced program. If e.g. a service is
  using the following unquoted path:

  C:\\Program Files\\Folder\\service.exe

  then a start of the service would first try to run:

  C:\\Program.exe

  and if not found:

  C:\\Program Files\\Folder\\service.exe

  afterwards. In this example the behavior allows a local attacker with low privileges and write
  permissions on C:\\ to place a malicious Program.exe which is then executed on a service/host
  restart or during the uninstallation of a software.

  NOTE: Currently only 'Services' using an unquoted path are reported as a vulnerability. The
  'Uninstall' vulnerability requires an Administrator / User to actively uninstall the affected
  software to trigger this vulnerability." );
	script_tag( name: "impact", value: "A local attacker could gain elevated privileges by inserting an
  executable file in the path of  the affected service or uninstall entry." );
	script_tag( name: "affected", value: "Software installing an 'Uninstall' registry entry or 'Service'
  on Microsoft Windows using an unquoted path containing at least one whitespace." );
	script_tag( name: "solution", value: "Either put the listed vulnerable paths in quotation by manually
  using the onboard Registry editor or contact your vendor to get an update for the specified
  software that fixes this vulnerability." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("host_details.inc.sc");
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!infos = kb_smb_wmi_connectinfo()){
	exit( 0 );
}
if(get_kb_item( "WMI/access_successful" )){
	handle = wmi_connect( host: infos["host"], username: infos["username_wmi_smb"], password: infos["password"] );
	if(handle){
		query = "SELECT DisplayName, Name, PathName FROM Win32_Service WHERE NOT PathName LIKE '%c:\\\\windows\\\\System32%' AND PathName LIKE '% %'";
		services = wmi_query( wmi_handle: handle, query: query );
		wmi_close( wmi_handle: handle );
		if(services){
			services_list = split( buffer: services, keep: FALSE );
			for service in services_list {
				if(service == "DisplayName|Name|PathName"){
					continue;
				}
				service_split = split( buffer: service, sep: "|", keep: FALSE );
				path_name = service_split[2];
				if(egrep( string: path_name, pattern: "^\".*\"" )){
					continue;
				}
				path_name = ereg_replace( string: path_name, pattern: "\\s+(/|\\-|\\-\\-).*", replace: "" );
				if(ContainsString( path_name, " " ) && !egrep( string: path_name, pattern: "^\".*\"" )){
					services_report += service + "\n";
					SERVICES_VULN = TRUE;
				}
			}
		}
	}
}
if(get_kb_item( "SMB/registry_access" )){
	for item in make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		 "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ) {
		itemList = registry_enum_keys( key: item );
		for key in itemList {
			fullKey = item + "\\" + key;
			uninstallstring = registry_get_sz( key: fullKey, item: "UninstallString" );
			if(strlen( uninstallstring ) > 0){
				if(egrep( string: uninstallstring, pattern: "^[a-zA-Z]:\\\\.*" )){
					_uninstallstring = ereg_replace( string: uninstallstring, pattern: "\\s+(/|\\-|\\-\\-).*", replace: "" );
					if(ContainsString( _uninstallstring, " " ) && !egrep( string: _uninstallstring, pattern: "^\".*\"" )){
						uninstall_report += fullKey + "|" + uninstallstring + "\n";
						UNINSTALL_VULN = TRUE;
					}
				}
			}
			quietuninstallstring = registry_get_sz( key: fullKey, item: "QuietUninstallString" );
			if(strlen( quietuninstallstring ) > 0){
				if(egrep( string: quietuninstallstring, pattern: "^[a-zA-Z]:\\\\.*" )){
					_quietuninstallstring = ereg_replace( string: quietuninstallstring, pattern: "\\s+(/|\\-|\\-\\-).*", replace: "" );
					if(ContainsString( _quietuninstallstring, " " ) && !egrep( string: _quietuninstallstring, pattern: "^\".*\"" )){
						uninstall_report += fullKey + "|" + quietuninstallstring + "\n";
						UNINSTALL_VULN = TRUE;
					}
				}
			}
		}
	}
}
if(SERVICES_VULN || UNINSTALL_VULN){
	if(UNINSTALL_VULN){
		report = "The following 'Uninstall' registry entries are using an 'unquoted' path:";
		report += "\n\nKey|Value\n";
		report += uninstall_report;
		log_message( port: 0, data: report );
	}
	if(SERVICES_VULN){
		report = "The following services are using an 'unquoted' service path:";
		report += "\n\nDisplayName|Name|PathName\n";
		report += services_report;
		security_message( port: 0, data: report );
	}
}
exit( 0 );

