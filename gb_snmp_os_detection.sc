if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103429" );
	script_version( "2021-09-15T10:02:34+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 10:02:34 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2012-02-17 10:17:12 +0100 (Fri, 17 Feb 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "SNMP sysDescr based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("cisco_ios.inc.sc");
require("snmp_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (SNMP)";
BANNER_TYPE = "SNMP sysDescr";
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "Linux" ) && ContainsString( sysdesc, " Debian " )){
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	if( ContainsString( sysdesc, "~bpo6" ) ){
		set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux 6.0" );
		os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		if( ContainsString( sysdesc, "+deb7" ) || ContainsString( sysdesc, "~bpo7" ) ){
			set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux 7" );
			os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( sysdesc, "+deb8" ) || ContainsString( sysdesc, "~bpo8" ) ){
				set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux 8" );
				os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( sysdesc, "+deb9" ) || ContainsString( sysdesc, "~bpo9" ) ){
					set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux 9" );
					os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( sysdesc, "+deb10" ) || ContainsString( sysdesc, "~bpo10" ) ){
						set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux 10" );
						os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						set_kb_item( name: "Host/OS/SNMP", value: "Debian GNU/Linux" );
						os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
			}
		}
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, " kernel [0-9]\\." )){
	set_kb_item( name: "Host/OS/SNMP", value: "Linux" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "kernel ([0-9]+\\.[^ ]*).*", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "Microsoft Corp. Windows 98" ) || IsMatchRegexp( sysdesc, "Hardware:.*Software: Windows" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Windows" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 75 );
	if(ContainsString( sysdesc, "Windows 98" )){
		os_register_and_report( os: "Microsoft Windows 98", cpe: "cpe:/o:microsoft:windows_98", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	version = eregmatch( pattern: "Software: Windows.*Version ([0-9.]+)", string: sysdesc );
	if(isnull( version[1] ) || ( !IsMatchRegexp( version[1], "^[4-6]\\.[0-3]" ) && !IsMatchRegexp( version[1], "^3\\.51?" ) )){
		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	winVal = version[1];
	if(winVal == "3.5"){
		os_register_and_report( os: "Microsoft Windows NT", version: "3.5", cpe: "cpe:/o:microsoft:windows_nt", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "3.51"){
		os_register_and_report( os: "Microsoft Windows NT", version: "3.51", cpe: "cpe:/o:microsoft:windows_nt", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "4.0"){
		os_register_and_report( os: "Microsoft Windows NT", version: "4.0", cpe: "cpe:/o:microsoft:windows_nt", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "5.0"){
		os_register_and_report( os: "Microsoft Windows 2000", cpe: "cpe:/o:microsoft:windows_2000", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "5.1"){
		os_register_and_report( os: "Microsoft Windows XP", cpe: "cpe:/o:microsoft:windows_xp", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "5.2"){
		os_register_and_report( os: "Microsoft Windows Server 2003 R2", cpe: "cpe:/o:microsoft:windows_server_2003:r2", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		os_register_and_report( os: "Microsoft Windows XP x64", cpe: "cpe:/o:microsoft:windows_xp:-:-:x64", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "6.0"){
		os_register_and_report( os: "Microsoft Windows Server 2008 or Microsoft Windows Vista", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "6.1"){
		os_register_and_report( os: "Microsoft Windows Server 2008 R2 or Microsoft Windows 7", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "6.2"){
		os_register_and_report( os: "Microsoft Windows Server 2012 or Microsoft Windows 8", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	if(winVal == "6.3"){
		os_register_and_report( os: "Microsoft Windows Server 2012 R2 or Microsoft Windows 8.1", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
		exit( 0 );
	}
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "(FreeBSD|pfSense).* FreeBSD" )){
	set_kb_item( name: "Host/OS/SNMP", value: "FreeBSD" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: ".*FreeBSD ([0-9.]+[^ ]*).*", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "FreeBSD", version: version[1], cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "NetBSD.* NetBSD" )){
	set_kb_item( name: "Host/OS/SNMP", value: "NetBSD" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: ".*NetBSD ([0-9.]+[^ ]*).*", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "NetBSD", version: version[1], cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^OpenBSD" ) || IsMatchRegexp( sysdesc, "Powered by OpenBSD" )){
	set_kb_item( name: "Host/OS/SNMP", value: "OpenBSD" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "OpenBSD.* ([0-9.]+) GENERIC", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "OpenBSD", version: version[1], cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^HP-UX" )){
	set_kb_item( name: "Host/OS/SNMP", value: "HP UX" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "^HP-UX [^ ]* ([^ ]*)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "HP HP-UX", version: version[1], cpe: "cpe:/o:hp:hp-ux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "HP HP-UX", cpe: "cpe:/o:hp:hp-ux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^SunOS" )){
	typ = " (sparc)";
	if(ContainsString( sysdesc, "i86pc" )){
		typ = " (i386)";
	}
	set_kb_item( name: "Host/OS/SNMP", value: "Sun Solaris" + typ );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "^SunOS .* (5\\.[0-9]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Sun SunOS", version: version[1], cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Sun SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "JETDIRECT" )){
	set_kb_item( name: "Host/OS/SNMP", value: "HP JetDirect Firmware" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	os_register_and_report( os: "HP JetDirect Firmware", cpe: "cpe:/o:hp:jetdirect_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "HP ETHERNET MULTI-ENVIRONMENT" )){
	os_register_and_report( os: "HP Ethernet Multi-Environment Firmware", cpe: "cpe:/o:hp:ethernet_multi-environment_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(( IsMatchRegexp( sysdesc, "^Cisco IOS" ) || ContainsString( sysdesc, "IOS (tm)" ) ) && ( !ContainsString( sysdesc, "Cisco IOS XR" ) && !IsMatchRegexp( sysdesc, "(IOS-XE|Virtual XE|CSR1000V) Software" ) )){
	set_kb_item( name: "Host/OS/SNMP", value: "Cisco IOS" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "IOS.*Version ([0-9]*\\.[0-9]*\\([0-9a-zA-Z]+\\)[A-Z0-9.]*),", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Cisco IOS", version: version[1], cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
		set_kb_item( name: "cisco_ios/snmp/version", value: version[1] );
		set_kb_item( name: "cisco_ios/detected", value: TRUE );
	}
	else {
		os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(( IsMatchRegexp( sysdesc, "^Cisco IOS" ) || ContainsString( sysdesc, "IOS (tm)" ) ) && !ContainsString( sysdesc, "Cisco IOS XR" ) && IsMatchRegexp( sysdesc, "(IOS-XE|Virtual XE|CSR1000V) Software" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Cisco IOS XE" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	os_register_and_report( os: "Cisco IOS XE", cpe: "cpe:/o:cisco:ios_xe", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "Base Operating System Runtime AIX" )){
	set_kb_item( name: "Host/OS/SNMP", value: "AIX" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "Base Operating System Runtime AIX version: ([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "IBM AIX", version: version[1], cpe: "cpe:/o:ibm:aix", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "IBM AIX", cpe: "cpe:/o:ibm:aix", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "^Darwin " ) || ContainsString( sysdesc, "Darwin Kernel" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Apple Mac OS X" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	os_register_and_report( os: "MAC OS X", cpe: "cpe:/o:apple:mac_os_x", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "Juniper Networks" ) && ContainsString( sysdesc, "JUNOS" )){
	set_kb_item( name: "Host/OS/SNMP", value: "JUNOS" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "JUNOS ([^ ]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Juniper JunOS", version: version[1], cpe: "cpe:/o:juniper:junos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Juniper JunOS", cpe: "cpe:/o:juniper:junos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "OpenVMS" )){
	set_kb_item( name: "Host/OS/SNMP", value: "OpenVMS" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "OpenVMS V([^ ]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "HP OpenVMS", version: version[1], cpe: "cpe:/o:hp:openvms", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "HP OpenVMS", cpe: "cpe:/o:hp:openvms", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "Novell NetWare" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Novell NetWare" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "Novell NetWare ([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Novell NetWare", version: version[1], cpe: "cpe:/o:novell:netware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Novell NetWare", cpe: "cpe:/o:novell:netware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "running IRIX(64)? version" )){
	set_kb_item( name: "Host/OS/SNMP", value: "IRIX" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "version ([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SGI IRIX", version: version[1], cpe: "cpe:/o:sgi:irix", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SGI IRIX", cpe: "cpe:/o:sgi:irix", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "SCO OpenServer" )){
	set_kb_item( name: "Host/OS/SNMP", value: "SCO OpenServer" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "SCO OpenServer Release ([0-9]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SCO OpenServer", version: version[1], cpe: "cpe:/o:sco:openserver", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SCO OpenServer", cpe: "cpe:/o:sco:openserver", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "SCO UnixWare" )){
	set_kb_item( name: "Host/OS/SNMP", value: "SCO UnixWare" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "SCO UnixWare ([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "SCO UnixWare", version: version[1], cpe: "cpe:/o:sco:unixware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "SCO UnixWare", cpe: "cpe:/o:sco:unixware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "Novell UnixWare" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Novell UnixWare" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "Novell UnixWare v([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Novell UnixWare", version: version[1], cpe: "cpe:/o:novell:unixware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Novell UnixWare", cpe: "cpe:/o:novell:unixware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(ContainsString( sysdesc, "ProSafe" ) || ContainsString( sysdesc, "ProSAFE" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Cisco IOS XR" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "ArubaOS" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Cisco NX-OS" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Cisco Adaptive Security Appliance" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Arista Networks EOS" )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^HyperIP" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Siemens, SIMATIC HMI" )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^SMS [^ ]+ v?SMS" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "Crestron Electronics AM-" )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^ ?LANCOM" )){
	exit( 0 );
}
if(ContainsString( sysdesc, "DGS-1500" )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^(ZyWall )?USG (FLEX )?[0-9]" )){
	os_register_and_report( os: "Zyxel USG Firmware", cpe: "cpe:/o:zyxel:usg_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^NetApp Release " )){
	os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^Ruckus Wireless ZD[0-9]+" )){
	os_register_and_report( os: "Ruckus ZoneDirector Firmware", cpe: "cpe:/o:ruckuswireless:zonedirector_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^(Aruba|HP|ProCurve) J[^ ]+ .*Switch" )){
	os_register_and_report( os: "Aruba/HP/HPE Switch Firmware", cpe: "cpe:/o:arubanetworks:switch_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^DrayTek.+Router Model" ) || IsMatchRegexp( sysdesc, "^DrayTek Corporation" ) || IsMatchRegexp( sysdesc, "^Linux Draytek " )){
	os_register_and_report( os: "DrayTek Vigor Firmware", cpe: "cpe:/o:draytek:vigor_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^cnPilot" )){
	os_register_and_report( os: "Cambium Networks cnPilot Firmware", cpe: "cpe:/o:cambiumnetworks:cnpilot_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "Option CloudGate" )){
	os_register_and_report( os: "Option CloudGate Firmware", cpe: "cpe:/o:option:cloudgate_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "(Cisco )?Network Analysis Module" ) && egrep( pattern: "Cisco Systems", string: sysdesc, icase: TRUE )){
	os_register_and_report( os: "Cisco NAM", cpe: "cpe:/o:cisco:prime_network_analysis_module_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "ZNID-GPON" ) || ContainsString( sysdesc, "Zhone Indoor Network Interface" )){
	os_register_and_report( os: "ZHONE ZNID GPON Firmware", cpe: "cpe:/o:dasanzhone:znid_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "S(G|F)[0-9]{3}.*(Stackable Managed|Managed|Smart) Switch$" )){
	os_register_and_report( os: "Cisco Small Business Switch Firmware", cpe: "cpe:/o:cisco:small_business_switch_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "HUAWEI VP9660" )){
	os_register_and_report( os: "Huawei VP9660 MCU Firmware", cpe: "cpe:/o:huawei:vp_9660_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "WatchGuard Fireware" )){
	set_kb_item( name: "Host/OS/SNMP", value: "WatchGuard Fireware" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "WatchGuard Fireware v([0-9.]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		register_product( cpe: "cpe:/o:watchguard:fireware:" + version[1] );
		os_register_and_report( os: "WatchGuard Fireware", version: version[1], cpe: "cpe:/o:watchguard:fireware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "WatchGuard Fireware", cpe: "cpe:/o:watchguard:fireware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "HP Comware (Platform )?Software" )){
	os_register_and_report( os: "HP Comware OS", cpe: "cpe:/o:hp:comware_os", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "Triax TDX" )){
	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(ContainsString( sysdesc, "IBM OS/400" )){
	version = eregmatch( pattern: "^IBM OS/400 ([^ ]+)", string: sysdesc );
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "IBM OS/400", version: tolower( version[1] ), cpe: "cpe:/o:ibm:os_400", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "IBM OS/400", cpe: "cpe:/o:ibm:os_400", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^SATO " )){
	os_register_and_report( os: "SATO Printer Firmware", cpe: "cpe:/o:sato:printer_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^KONICA MINOLTA " )){
	os_register_and_report( os: "KONICA MINOLTA Printer Firmware", cpe: "cpe:/o:konicaminolta:printer_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( pattern: "VxWorks", string: sysdesc, icase: TRUE )){
	os_register_and_report( os: "Wind River VxWorks", cpe: "cpe:/o:windriver:vxworks", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(egrep( pattern: "^Westermo.*, primary:.*, backup:.*, bootloader:", string: sysdesc, icase: TRUE )){
	os_register_and_report( os: "Westermo WeOS", cpe: "cpe:/o:westermo:weos", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^EPSON " )){
	os_register_and_report( os: "Epson Printer Firmware", cpe: "cpe:/o:epson:printer_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "Linux" ) && !ContainsString( sysdesc, "Cisco IOS" )){
	set_kb_item( name: "Host/OS/SNMP", value: "Linux" );
	set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
	version = eregmatch( pattern: "Linux [^ ]* ([0-9]+\\.[^ ]*).*", string: sysdesc );
	if(version[1]){
		if(IsMatchRegexp( version[1], "\\.h[0-9]+" )){
			os_register_and_report( os: "Huawei EulerOS", cpe: "cpe:/o:huawei:euleros", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( version[1], ".el" ) && ContainsString( version[1], "uek." )){
			version = eregmatch( pattern: "\\.el([0-9]+)", string: version[1] );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Oracle Linux", version: version[1], cpe: "cpe:/o:oracle:linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Oracle Linux", cpe: "cpe:/o:oracle:linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			exit( 0 );
		}
		if(ContainsString( version[1], ".el" )){
			version = eregmatch( pattern: "\\.el([0-9]+)", string: version[1] );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Red Hat Enterprise Linux / CentOS", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Red Hat Enterprise Linux / CentOS", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			exit( 0 );
		}
		if(ContainsString( version[1], ".fc" )){
			version = eregmatch( pattern: "\\.fc([0-9]+)", string: version[1] );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Fedora Core", version: version[1], cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Fedora Core", cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			exit( 0 );
		}
	}
	if( !isnull( version[1] ) ){
		os_register_and_report( os: "Linux", version: version[1], cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "^Siemens, SIMOCODE" )){
	os_register_and_report( os: "Siemens SIMOCODE Firmware", cpe: "cpe:/o:siemens:simocode_firmware", banner_type: BANNER_TYPE, port: port, proto: "udp", banner: sysdesc, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
os_register_unknown_banner( banner: sysdesc, banner_type_name: BANNER_TYPE, banner_type_short: "snmp_sysdesc_banner", port: port, proto: "udp" );
exit( 0 );

