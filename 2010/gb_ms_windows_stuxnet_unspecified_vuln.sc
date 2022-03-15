if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801527" );
	script_version( "$Revision: 12978 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2010-10-18 15:37:53 +0200 (Mon, 18 Oct 2010)" );
	script_cve_id( "CVE-2010-3888", "CVE-2010-3889" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft Windows 32-bit Platforms Unspecified vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://www.virusbtn.com/conference/vb2010/abstracts/LastMinute8.xml" );
	script_xref( name: "URL", value: "http://www.virusbtn.com/conference/vb2010/abstracts/LastMinute7.xml" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/blog/2291/Myrtus_and_Guava_Episode_MS10_061" );
	script_xref( name: "URL", value: "http://www.computerworld.com/s/article/9185919/Is_Stuxnet_the_best_malware_ever_" );
	script_xref( name: "URL", value: "http://www.symantec.com/connect/blogs/stuxnet-using-three-additional-zero-day-vulnerabilities" );
	script_tag( name: "impact", value: "Successful exploitation could allow local attackers to gain privileges or
  compromise the vulnerable system via unknown vectors." );
	script_tag( name: "affected", value: "All Windows platforms" );
	script_tag( name: "insight", value: "Unspecified privilege elevation vulnerabilities that are used by variants of
  the 'Stuxnet malware' family. Each of these vulnerabilities allow the malware
  to elevate its privileges to higher than normal user levels in order to embed
  itself into the operating system and prevent disinfection and/or detection." );
	script_tag( name: "solution", value: "Remove all Stuxnet related files found." );
	script_tag( name: "summary", value: "This host is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
rootfile = smb_get_systemroot();
if(!rootfile){
	exit( 0 );
}
stux = make_list( "\\system32\\winsta.exe",
	 "\\system32\\mof\\sysnullevent.mof" );
for file in stux {
	path = rootfile + file;
	read = smb_read_file( fullpath: path, offset: 0, count: 30 );
	if(read){
		security_message( port: 0, data: "The target host was found to be vulnerable based on the existence of the following file: " + file );
		exit( 0 );
	}
}
exit( 99 );

