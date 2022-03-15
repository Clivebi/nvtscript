if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800491" );
	script_version( "$Revision: 12602 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-0103" );
	script_bugtraq_id( 38571 );
	script_name( "Energizer DUO USB Battery Charger Software Backdoor" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/154421" );
	script_xref( name: "URL", value: "http://www.threatexpert.com/report.aspx?md5=3f4f10b927677e45a495d0cdd4390aaf" );
	script_xref( name: "URL", value: "http://www.symantec.com/connect/blogs/trojan-found-usb-battery-charger-software" );
	script_xref( name: "URL", value: "http://www.marketwatch.com/story/energizer-announces-duo-charger-and-usb-charger-software-problem-2010-03-05" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
	script_tag( name: "impact", value: "Successful exploitation let attackers to remotely control a
  system, including the ability to list directories. The backdoor operates
  with the privileges of the logged-on user." );
	script_tag( name: "affected", value: "Energizer DUO USB Battery Charger Software" );
	script_tag( name: "insight", value: "As part of the installation process of 'USB charger software package',
  a file 'Arucer.dll' is created and added to the registry run key and this file
  is the Trojan. Trojan listens for commands from anyone who connects and can
  perform various actions, such as:

  - Download a file

  - Execute a file

  - Send a directory/files listing to the remote attacker" );
	script_tag( name: "summary", value: "This host is installed with Energizer DUO USB Battery Charger
  Software which contains a backdoor." );
	script_tag( name: "solution", value: "Remove the Energizer UsbCharger software and
  follow the instruction specified in the references." );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
if(!get_kb_item( "SMB/WindowsVersion" )){
	exit( 0 );
}
if(registry_key_exists( key: "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" )){
	dllPath = registry_get_sz( key: "SOFTWARE\\Microsoft\\COM3\\Setup", item: "Install Path" );
	if(!dllPath){
		exit( 0 );
	}
	share = ereg_replace( pattern: "([A-Z]):.*", replace: "\\1$", string: dllPath );
	file = ereg_replace( pattern: "[A-Z]:(.*)", replace: "\\1", string: dllPath + "\\Arucer.dll" );
	dllVer = GetVer( file: file, share: share );
	if(!isnull( dllVer )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
	}
}

