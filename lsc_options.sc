if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100509" );
	script_version( "2021-08-04T09:09:05+0000" );
	script_tag( name: "last_modification", value: "2021-08-04 09:09:05 +0000 (Wed, 04 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-02-26 12:01:21 +0100 (Fri, 26 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Options for Local Security Checks" );
	script_category( ACT_SETTINGS );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Settings" );
	script_add_preference( name: "Also use 'find' command to search for Applications", type: "checkbox", value: "yes", id: 1 );
	script_add_preference( name: "Descend directories on other filesystem (don't add -xdev to find)", type: "checkbox", value: "yes", id: 2 );
	script_add_preference( name: "Enable Detection of Portable Apps on Windows", type: "checkbox", value: "no", id: 3 );
	script_add_preference( name: "Disable the usage of win_cmd_exec for remote commands on Windows", type: "checkbox", value: "no", id: 4 );
	script_add_preference( name: "Disable file search via WMI on Windows", type: "checkbox", value: "no", id: 5 );
	script_add_preference( name: "Report vulnerabilities of inactive Linux Kernel(s) separately", type: "checkbox", value: "no", id: 6 );
	script_add_preference( name: "Integer that sets the directory depth when using 'find' on unixoide systems", type: "entry", value: "12", id: 7 );
	script_add_preference( name: "Use 'su - USER' option on SSH commands", type: "radio", value: "no;yes", id: 8 );
	script_add_preference( name: "Use this user for 'su - USER' option on SSH commands", type: "entry", value: "", id: 9 );
	script_add_preference( name: "Folder exclusion regex for file search on Unixoide targets", type: "entry", value: "^/(afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|lost\\+found|mail|opt|run|spool|tmp)|etc/init\\.d|usr/share/doc)", id: 10 );
	script_tag( name: "summary", value: "This script allows users to set some Options for Local Security
  Checks which are stored in the knowledge base and used by other tests. Description of the options:

  - Also use 'find' command to search for Applications:

  Setting this option to 'no' disables the use of the 'find' command via SSH against Unixoide
  targets. This reduces scan time but might reduce detection coverage of e.g. local installed
  applications.

  - Descend directories on other filesystem (don't add -xdev to find):

  During the scan 'find' is used to detect e.g. local installed applications via SSH on Unixoide
  targets. This command is descending on special (network-)filesystems like NFS, SMB or similar
  mounted on the target host by default. Setting this option to 'no' might reduce the scan time if
  network based filesystems are not searched for installed applications.

  - Enable Detection of Portable Apps on Windows:

  Setting this option to 'yes' enables the Detection of Portable Apps on Windows via WMI. Enabling
  this option might increase scan time as well as the load on the target host.

  - Disable the usage of win_cmd_exec for remote commands on Windows:

  Some AV solutions might block remote commands called on the remote host via a scanner internal
  'win_cmd_exe' function. Setting this option to 'yes' disables the usage of this function (as a
  workaround for issues during the scan) with the risk of lower scan coverage against Windows
  targets.

  - Disable file search via WMI on Windows:

  Various VTs are using WMI to search for files on Windows targets. Depending on the attached
  storage and its size this routine might put high load on the target and could slow down the scan.
  Setting this option to 'yes' disables the usage of this search with the risk of lower scan
  coverage against Windows targets.

  - Report vulnerabilities of inactive Linux Kernel(s) separately:

  All current package manager based Local Security Checks are reporting the same severity for active
  and inactive Linux Kernel(s). If this setting is enabled the reporting for inactive Linux
  Kernel(s) is done separately in the VT 'Report Vulnerabilities in inactive Linux Kernel(s)'
  (OID: 1.3.6.1.4.1.25623.1.0.108545).

  Please note that this functionality is currently only available for Debian (and Derivates using
  apt-get) and RPM based Distributions and needs to be considered as 'experimental'.

  - Integer that sets the directory depth when using 'find' on unixoide systems:

  A non-negative integer added as '-maxdepth' parameter to all 'find' calls used during a scan of
  unixoide systems.

  - Use 'su - USER' option on SSH commands and Use this user for 'su - USER' option on SSH commands:

  Deprecated preferences / options which will be removed in the future. Please migrate to the new
  'Elevate Privileges' feature introduced in GOS/GVM 21.04.5. See the references for more
  information.

  - Folder exclusion regex for file search on Unixoide targets:

  During the scan 'find' and/or 'locate' is used to detect e.g. local installed applications via SSH
  on Unixoide targets. This option allows to pass a regex to define which folders should be excluded
  / not searched when searching for files on such a target. Please pass 'None' to the option if you
  don't want to exclude any folders." );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-21.04/en/scanning.html#creating-a-target" );
	script_tag( name: "qod_type", value: "general_note" );
	exit( 0 );
}
find_enabled = script_get_preference( name: "Also use 'find' command to search for Applications", id: 1 );
nfs_search_enabled = script_get_preference( name: "Descend directories on other filesystem (don't add -xdev to find)", id: 2 );
search_portable = script_get_preference( name: "Enable Detection of Portable Apps on Windows", id: 3 );
disable_win_cmd_exec = script_get_preference( name: "Disable the usage of win_cmd_exec for remote commands on Windows", id: 4 );
disable_wmi_search = script_get_preference( name: "Disable file search via WMI on Windows", id: 5 );
kernel_overwrite = script_get_preference( name: "Report vulnerabilities of inactive Linux Kernel(s) separately", id: 6 );
find_maxdepth = script_get_preference( name: "Integer that sets the directory depth when using 'find' on unixoide systems", id: 7 );
use_su = script_get_preference( name: "Use 'su - USER' option on SSH commands", id: 8 );
su_user = script_get_preference( name: "Use this user for 'su - USER' option on SSH commands", id: 9 );
unix_search_excl = script_get_preference( name: "Folder exclusion regex for file search on Unixoide targets", id: 10 );
if(find_enabled){
	set_kb_item( name: "ssh/lsc/enable_find", value: find_enabled );
}
if(nfs_search_enabled){
	set_kb_item( name: "ssh/lsc/descend_ofs", value: nfs_search_enabled );
}
if(kernel_overwrite && ContainsString( kernel_overwrite, "yes" )){
	set_kb_item( name: "ssh/login/kernel_reporting_overwrite/enabled", value: TRUE );
}
if(search_portable && ContainsString( search_portable, "yes" )){
	set_kb_item( name: "win/lsc/search_portable_apps", value: TRUE );
}
if(disable_win_cmd_exec && ContainsString( disable_win_cmd_exec, "yes" )){
	set_kb_item( name: "win/lsc/disable_win_cmd_exec", value: TRUE );
}
if(disable_wmi_search && ContainsString( disable_wmi_search, "yes" )){
	set_kb_item( name: "win/lsc/disable_wmi_search", value: TRUE );
}
if(!isnull( find_maxdepth )){
	if(!find_maxdepth){
		find_maxdepth = "zero";
	}
	set_kb_item( name: "ssh/lsc/find_maxdepth", value: find_maxdepth );
}
if(use_su && ContainsString( use_su, "yes" )){
	set_kb_item( name: "ssh/lsc/use_su", value: "yes" );
	if( !isnull( su_user ) ){
		if( !su_user ){
			replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
		}
		else {
			set_kb_item( name: "ssh/lsc/su_user", value: su_user );
			log_message( port: 0, data: "Deprecated 'su - USER' preferences configured which will be removed in the future. Please migrate to the new 'Elevate Privileges' feature introduced in GOS/GVM 21.04.5. See the references for more information." );
		}
	}
	else {
		replace_kb_item( name: "ssh/lsc/use_su", value: "no" );
	}
}
if( unix_search_excl ){
	set_kb_item( name: "ssh/lsc/search_exclude_paths", value: unix_search_excl );
}
else {
	set_kb_item( name: "ssh/lsc/search_exclude_paths", value: "^/(afs|dev|media|mnt|net|run|sfs|sys|tmp|udev|var/(backups|cache|lib|local|lock|log|lost\\+found|mail|opt|run|spool|tmp)|etc/init\\.d|usr/share/doc)" );
}
exit( 0 );

