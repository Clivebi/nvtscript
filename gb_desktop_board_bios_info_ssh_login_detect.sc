if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800163" );
	script_version( "2021-06-07T11:59:32+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-07 11:59:32 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)" );
	script_name( "BIOS and Hardware Information Detection (Linux/Unix SSH Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_dmidecode_ssh_login_detect.sc" );
	script_mandatory_keys( "dmidecode/ssh-login/full_permissions" );
	script_tag( name: "summary", value: "SSH login-based gathering of various BIOS and Hardware related
  information." );
	script_tag( name: "vuldetect", value: "Logs in via SSH and queries the BIOS and Hardware related
  information using the command line tool 'dmidecode'. Usually this command requires root privileges
  to execute." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
if(!get_kb_item( "dmidecode/ssh-login/full_permissions" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
SCRIPT_DESC = "BIOS and Hardware Information Detection (Linux/Unix SSH Login)";
bios_ver = ssh_cmd( socket: sock, cmd: "dmidecode -s bios-version", timeout: 120 );
bios_ver = chomp( bios_ver );
bios_vendor = ssh_cmd( socket: sock, cmd: "dmidecode -s bios-vendor", timeout: 120 );
bios_vendor = chomp( bios_vendor );
base_board_ver = ssh_cmd( socket: sock, cmd: "dmidecode -s baseboard-version", timeout: 120 );
base_board_ver = chomp( base_board_ver );
base_board_manu = ssh_cmd( socket: sock, cmd: "dmidecode -s baseboard-manufacturer", timeout: 120 );
base_board_manu = chomp( base_board_manu );
base_board_prod_name = ssh_cmd( socket: sock, cmd: "dmidecode -s baseboard-product-name", timeout: 120 );
base_board_prod_name = chomp( base_board_prod_name );
ssh_close_connection();
report = "";
if(bios_ver && strlen( bios_ver ) > 0 && !IsMatchRegexp( bios_ver, "(command not found|dmidecode:|permission denied)" )){
	set_kb_item( name: "DesktopBoards/BIOS/Ver", value: bios_ver );
	report += "BIOS version: " + bios_ver + "\n";
	register_host_detail( name: "BIOSVersion", value: bios_ver, desc: SCRIPT_DESC );
}
if(bios_vendor && strlen( bios_vendor ) > 0 && !IsMatchRegexp( bios_vendor, "(command not found|dmidecode:|permission denied)" )){
	set_kb_item( name: "DesktopBoards/BIOS/Vendor", value: bios_vendor );
	report += "BIOS Vendor: " + bios_vendor + "\n";
	register_host_detail( name: "BIOSVendor", value: bios_vendor, desc: SCRIPT_DESC );
}
if(base_board_ver && strlen( base_board_ver ) > 0 && !IsMatchRegexp( base_board_ver, "(command not found|dmidecode:|permission denied)" )){
	set_kb_item( name: "DesktopBoards/BaseBoard/Ver", value: base_board_ver );
	report += "Base Board version: " + base_board_ver + "\n";
	register_host_detail( name: "BaseBoardVersion", value: base_board_ver, desc: SCRIPT_DESC );
}
if(base_board_manu && strlen( base_board_manu ) > 0 && !IsMatchRegexp( base_board_manu, "(command not found|dmidecode:|permission denied)" )){
	set_kb_item( name: "DesktopBoards/BaseBoard/Manufacturer", value: base_board_manu );
	report += "Base Board Manufacturer: " + base_board_manu + "\n";
	register_host_detail( name: "BaseBoardManufacturer", value: base_board_manu, desc: SCRIPT_DESC );
}
if(base_board_prod_name && strlen( base_board_prod_name ) > 0 && !IsMatchRegexp( base_board_prod_name, "(command not found|dmidecode:|permission denied)" )){
	set_kb_item( name: "DesktopBoards/BaseBoard/ProdName", value: base_board_prod_name );
	report += "Base Board Product Name: " + base_board_prod_name + "\n";
	register_host_detail( name: "BaseBoardProduct", value: base_board_prod_name, desc: SCRIPT_DESC );
}
if(report){
	log_message( port: 0, data: chomp( report ) );
}
exit( 0 );

