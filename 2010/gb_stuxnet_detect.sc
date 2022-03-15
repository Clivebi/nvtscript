if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100815" );
	script_version( "$Revision: 12978 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-01-08 15:15:07 +0100 (Tue, 08 Jan 2019) $" );
	script_tag( name: "creation_date", value: "2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Stuxnet Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "http://vil.nai.com/vil/Content/v_268468.htm" );
	script_xref( name: "URL", value: "http://www.stuxnet.net/" );
	script_tag( name: "summary", value: "The remote Host seems to be infected by the Stuxnet worm.

  The Scanner found files on the remote host that indicate that this host is
  infected by the Stuxnet worm." );
	script_tag( name: "solution", value: "Remove all Stuxnet related files found." );
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
stux = make_list( "system32\\s7otbxsx.dll",
	 "inf\\mdmcpq3.PNF",
	 "inf\\mdmeric3.PNF",
	 "inf\\oem6C.PNF",
	 "inf\\oem7A.PNF",
	 "system32\\drivers\\mrxcls.sys",
	 "system32\\drivers\\mrxnet.sys" );
report = NASLString( "The following Stuxnet related files are detected on the remote Host:\\n\\n" );
for file in stux {
	my_file = NASLString( rootfile, "\\", file );
	myread = smb_read_file( fullpath: my_file, offset: 0, count: 8 );
	if(myread){
		stux_found = TRUE;
		report += my_file + "\n";
	}
}
if(stux_found){
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

