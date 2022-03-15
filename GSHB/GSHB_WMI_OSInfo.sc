if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96999" );
	script_version( "$Revision: 10695 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-31 17:51:04 +0200 (Tue, 31 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2009-10-23 12:32:24 +0200 (Fri, 23 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Get OS Version, OS Type, OS Servicepack and OS Name over WMI (win)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2009 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "gb_wmi_access.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_tag( name: "summary", value: "Get OS Version, OS Type, OS Servicepack and OS Name over WMI (win)" );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("wmi_os.inc.sc");
require("smb_nt.inc.sc");
host = get_host_ip();
usrname = kb_smb_login();
domain = kb_smb_domain();
if(domain){
	usrname = domain + "\\" + usrname;
}
passwd = kb_smb_password();
samba = kb_smb_is_samba();
errorval = "none";
if(samba){
	set_kb_item( name: "WMI/WMI_WindowsDomain", value: errorval );
	set_kb_item( name: "WMI/WMI_WindowsDomainrole", value: errorval );
	set_kb_item( name: "WMI/WMI_OSVER", value: errorval );
	set_kb_item( name: "WMI/WMI_OSSP", value: errorval );
	set_kb_item( name: "WMI/WMI_OSTYPE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSDRIVE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSWINDIR", value: errorval );
	set_kb_item( name: "WMI/WMI_OSNAME", value: errorval );
	set_kb_item( name: "WMI/WMI_OS/log", value: "On the Target System runs Samba, it is not an Microsoft System." );
	exit( 0 );
}
if(!host || !usrname || !passwd){
	set_kb_item( name: "WMI/WMI_WindowsDomain", value: errorval );
	set_kb_item( name: "WMI/WMI_WindowsDomainrole", value: errorval );
	set_kb_item( name: "WMI/WMI_OSVER", value: errorval );
	set_kb_item( name: "WMI/WMI_OSSP", value: errorval );
	set_kb_item( name: "WMI/WMI_OSTYPE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSDRIVE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSWINDIR", value: errorval );
	set_kb_item( name: "WMI/WMI_OSNAME", value: errorval );
	set_kb_item( name: "WMI/WMI_OS/log", value: "No Host, Username or Password." );
	exit( 0 );
}
wmi_access = get_kb_item( "WMI/access_successful" );
if(wmi_access){
	handle = wmi_connect( host: host, username: usrname, password: passwd );
}
if(!handle){
	set_kb_item( name: "WMI/WMI_WindowsDomain", value: errorval );
	set_kb_item( name: "WMI/WMI_WindowsDomainrole", value: errorval );
	set_kb_item( name: "WMI/WMI_OSVER", value: errorval );
	set_kb_item( name: "WMI/WMI_OSSP", value: errorval );
	set_kb_item( name: "WMI/WMI_OSTYPE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSDRIVE", value: errorval );
	set_kb_item( name: "WMI/WMI_OSWINDIR", value: errorval );
	set_kb_item( name: "WMI/WMI_OSNAME", value: errorval );
	set_kb_item( name: "WMI/WMI_OS/log", value: "wmi_connect: WMI Connect failed." );
	exit( 0 );
}
query1 = "select Caption from Win32_OperatingSystem";
query2 = "select Domain from Win32_ComputerSystem";
query3 = "select DomainRole from Win32_ComputerSystem";
query4 = "select OSArchitecture from Win32_OperatingSystem";
OSVER = wmi_os_version( handle: handle );
OSSP = wmi_os_sp( handle: handle );
if( OSSP != 1 ){
	OSSP = eregmatch( pattern: "[0-9]", string: OSSP );
	OSSP = OSSP[0];
}
else {
	OSSP = "Without SP";
}
OSTYPE = wmi_os_type( handle: handle );
OSArchitecture = wmi_query( wmi_handle: handle, query: query4 );
OSArchitecture = split( buffer: OSArchitecture, sep: "\n", keep: FALSE );
OSNAME = wmi_query( wmi_handle: handle, query: query1 );
OSNAME = split( buffer: OSNAME, sep: "\n", keep: FALSE );
if( OSVER <= 6 ){
	OSNAME = split( buffer: OSNAME[1], sep: "|", keep: FALSE );
	OSNAME = OSNAME[0];
}
else {
	OSNAME = OSNAME[1];
}
Domain = wmi_query( wmi_handle: handle, query: query2 );
Domain = split( buffer: Domain, sep: "\n", keep: FALSE );
Domain = split( buffer: Domain[1], sep: "|", keep: FALSE );
Domain = Domain[0];
windirpath = wmi_os_windir( handle: handle );
if( OSVER < 6 ){
	val01 = split( buffer: windirpath, sep: "|", keep: FALSE );
	val02 = split( buffer: val01[4], sep: "\\", keep: FALSE );
	OSDRIVE = val02[0];
}
else {
	val01 = split( buffer: windirpath, sep: ":", keep: FALSE );
	val04 = eregmatch( pattern: "[A-Z]$", string: val01[0] );
	OSDRIVE = val04[0] + ":";
}
OSWINDIR = wmi_os_windir( handle: handle );
if( OSVER < "6.0" ){
	OSWINDIR = split( buffer: OSWINDIR, sep: "|", keep: FALSE );
	OSWINDIR = ereg_replace( pattern: "\n", string: OSWINDIR[4], replace: "" );
}
else {
	OSWINDIR = split( buffer: OSWINDIR, sep: "\n", keep: FALSE );
	OSWINDIR = OSWINDIR[1];
}
Domainrole = wmi_query( wmi_handle: handle, query: query3 );
wmi_close( wmi_handle: handle );
if( !Domainrole ){
	Domainrole = "none";
}
else {
	Domainrole = split( buffer: Domainrole, sep: "\n", keep: FALSE );
	Domainrole = split( buffer: Domainrole[1], sep: "|", keep: FALSE );
	Domainrole = Domainrole[0];
}
if(!OSVER){
	OSVER = errorval;
}
if(!OSSP){
	OSSP = errorval;
}
if(!OSTYPE){
	OSTYPE = errorval;
}
if(!OSArchitecture[1]){
	OSArchitecture[1] = errorval;
}
if(!OSNAME){
	OSNAME = errorval;
}
if(!OSDRIVE){
	OSDRIVE = errorval;
}
if(!OSWINDIR){
	OSWINDIR = errorval;
}
if(!Domain){
	Domain = errorval;
}
set_kb_item( name: "WMI/WMI_WindowsDomain", value: Domain );
set_kb_item( name: "WMI/WMI_WindowsDomainrole", value: Domainrole );
set_kb_item( name: "WMI/WMI_OSVER", value: OSVER );
set_kb_item( name: "WMI/WMI_OSSP", value: OSSP );
set_kb_item( name: "WMI/WMI_OSTYPE", value: OSTYPE );
set_kb_item( name: "WMI/WMI_OSArchitecture", value: OSArchitecture[1] );
set_kb_item( name: "WMI/WMI_OSDRIVE", value: OSDRIVE );
set_kb_item( name: "WMI/WMI_OSWINDIR", value: OSWINDIR );
set_kb_item( name: "WMI/WMI_OSNAME", value: OSNAME );
set_kb_item( name: "WMI/WMI_OS/log", value: "ok" );
exit( 0 );

