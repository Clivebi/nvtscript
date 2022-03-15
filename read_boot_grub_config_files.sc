if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150178" );
	script_version( "2021-01-12T09:19:29+0000" );
	script_tag( name: "last_modification", value: "2021-01-12 09:19:29 +0000 (Tue, 12 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-03-23 13:25:47 +0000 (Mon, 23 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Linux: Read GRUB config files (KB)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "gather-package-list.sc", "compliance_tests.sc" );
	script_mandatory_keys( "Compliance/Launch" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_xref( name: "URL", value: "https://www.tutorialspoint.com/what-is-grub-in-linux" );
	script_tag( name: "summary", value: "The GRUB (Grand Unified Bootloader) is a bootloader available
from the GNU project. A bootloader is very important as it is impossible to start an operating
system without it. It is the first program which starts when the program is switched on. The
bootloader transfers the control to the operating system kernel.

This script searches for grub.cfg, menu.lst and user.cfg in /boot/ directory.

Note: This script only stores information for other Policy Controls." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("policy_functions.inc.sc");
if(!get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection()){
	set_kb_item( name: "Policy/linux/grub/ssh/ERROR", value: TRUE );
	exit( 0 );
}
bootloader_files = make_list();
grub_cfg_files = ssh_find_file( file_name: "grub.cfg", sock: sock, useregex: FALSE );
menu_lst_files = ssh_find_file( file_name: "menu.lst", sock: sock, useregex: FALSE );
user_cfg_files = ssh_find_file( file_name: "user.cfg", sock: sock, useregex: FALSE );
if(grub_cfg_files){
	bootloader_files = make_list( bootloader_files,
		 grub_cfg_files );
}
if(menu_lst_files){
	bootloader_files = make_list( bootloader_files,
		 menu_lst_files );
}
if(user_cfg_files){
	bootloader_files = make_list( bootloader_files,
		 user_cfg_files );
}
for file in bootloader_files {
	file = chomp( file );
	set_kb_item( name: "Policy/linux/grub/files/", value: file );
	policy_linux_stat_file( socket: sock, file: file );
	policy_linux_file_content( socket: sock, file: file );
}
exit( 0 );

