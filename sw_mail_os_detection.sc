if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111068" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2015-12-11 14:00:00 +0100 (Fri, 11 Dec 2015)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (SMTP/POP3/IMAP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_dependencies( "smtpserver_detect.sc", "popserver_detect.sc", "imap4_banner.sc" );
	script_require_ports( "Services/smtp", 25, 465, 587, "Services/pop3", 110, 995, "Services/imap", 143, 993 );
	script_mandatory_keys( "pop3_imap_or_smtp/banner/available" );
	script_tag( name: "summary", value: "SMTP/POP3/IMAP banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("smtp_func.inc.sc");
require("imap_func.inc.sc");
require("pop3_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (SMTP/POP3/IMAP)";
ports = smtp_get_ports();
banner_type = "SMTP banner";
for port in ports {
	banner = smtp_get_banner( port: port );
	if(!banner){
		continue;
	}
	if(ContainsString( banner, "ESMTP" ) || IsMatchRegexp( banner, "^[0-9]{3}[ -].+" )){
		if(banner == "220 ESMTP"){
			continue;
		}
		if(egrep( pattern: "^220 [^ ]+ ESMTP( Postfix| ready\\.)?$", string: banner )){
			continue;
		}
		if(egrep( pattern: "ESMTP Exim [0-9._]+ ", string: banner )){
			continue;
		}
		if(ContainsString( banner, "(Gentoo Linux" ) || ContainsString( banner, "(GENTOO/GNU)" ) || ContainsString( banner, "(Gentoo/GNU)" ) || ContainsString( banner, "(Gentoo powered" ) || ContainsString( banner, "(Gentoo)" ) || ContainsString( banner, " Gentoo" ) || ContainsString( banner, "(Gentoo/Linux" )){
			os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "Xpressions" ) && ContainsString( banner, "(WIN-NT)" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			continue;
		}
		if(ContainsString( banner, "MDaemon" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			continue;
		}
		if(ContainsString( banner, "(Ubuntu)" ) || ContainsString( banner, "ubuntu" ) || ContainsString( banner, " Ubuntu " )){
			os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "ESMTP AIX Sendmail" ) || ContainsString( banner, "ESMTP sendmail (AIX/" ) || ContainsString( banner, " (IBM AIX " ) || ContainsString( banner, "ESMTP Sendmail AIX" ) || ContainsString( banner, "ESMTP (AIX/IBM)" ) || ContainsString( banner, "IBM PROFs ESMTP gateway AIX" )){
			version = eregmatch( pattern: "(\\(IBM AIX | AIX ?)([0-9.]+)[)/ ]", string: banner, icase: FALSE );
			if( !isnull( version[2] ) ){
				os_register_and_report( os: "IBM AIX", version: version[2], cpe: "cpe:/o:ibm:aix", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "IBM AIX", cpe: "cpe:/o:ibm:aix", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(Debian/GNU)" ) || ContainsString( banner, "/Debian-" )){
			if( ContainsString( banner, "sarge" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "(Debian Lenny)" ) || ContainsString( banner, "lenny" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "deb7" ) || ContainsString( banner, "wheezy" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "deb8" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
					}
				}
			}
			continue;
		}
		if(ContainsString( banner, "/SuSE Linux" ) || ContainsString( banner, "(Linux Suse" ) || ContainsString( banner, "on SuSE Linux" ) || ContainsString( banner, "(SuSE)" )){
			os_register_and_report( os: "SUSE Linux", cpe: "cpe:/o:novell:suse_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(CentOS)" ) || ContainsString( banner, "(Centos Linux)" ) || ContainsString( banner, "(CentOS/GNU)" )){
			os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "on Red Hat Enterprise Linux" ) || ContainsString( banner, "(Red Hat Enterprise Linux)" ) || ContainsString( banner, "(RHEL" ) || ContainsString( banner, "(RHEL/GNU)" )){
			version = eregmatch( pattern: "\\(RHEL ([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "Red Hat Linux" )){
			os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(OpenBSD" ) || ContainsString( banner, " OpenBSD" )){
			version = eregmatch( pattern: "\\(OpenBSD ([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "OpenBSD", version: version[1], cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(FreeBSD" ) || ContainsString( banner, "Powered By FreeBSD" ) || ContainsString( banner, "FreeBSD/" ) || ContainsString( banner, " FreeBSD" ) || ContainsString( banner, "-FreeBSD" )){
			version = eregmatch( pattern: "\\(FreeBSD( |/)([0-9.]+)", string: banner );
			if( !isnull( version[2] ) ){
				os_register_and_report( os: "FreeBSD", version: version[2], cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(NetBSD" ) || ContainsString( banner, "/NetBSD" ) || ContainsString( banner, "[NetBSD]" ) || ContainsString( banner, " NetBSD " )){
			os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(Fedora" )){
			if( ContainsString( banner, "(Fedora Core" ) ){
				version = eregmatch( pattern: "\\(Fedora Core ([0-9.]+)", string: banner );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Fedora Core", version: version[1], cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Fedora Core", cpe: "cpe:/o:fedoraproject:fedora_core", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
			}
			else {
				version = eregmatch( pattern: "\\(Fedora ([0-9.]+)", string: banner );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Fedora", version: version[1], cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
			}
			continue;
		}
		if(ContainsString( banner, "(SunOS" ) || ContainsString( banner, " SunOS " ) || ContainsString( banner, "Sun/" )){
			version = eregmatch( pattern: "\\(SunOS ([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "SunOS", version: version[1], cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(Mageia" )){
			version = eregmatch( pattern: "\\(Mageia ([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Mageia", version: version[1], cpe: "cpe:/o:mageia:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Mageia", cpe: "cpe:/o:mageia:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(Mandriva" )){
			version = eregmatch( pattern: "\\(Mandriva MES([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Mandriva Enterprise Server", version: version[1], cpe: "cpe:/o:mandriva:enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Mandriva", cpe: "cpe:/o:mandriva:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "(Mandrake" )){
			os_register_and_report( os: "Mandrake", cpe: "cpe:/o:mandrakesoft:mandrake_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(Slackware" )){
			os_register_and_report( os: "Slackware", cpe: "cpe:/o:slackware:slackware_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, " ESMTP Exim " )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, " IceWarp " )){
			if( os_info = eregmatch( pattern: "IceWarp ([^ ;]+) ([^ ;]+) ([^ ;]+); ", string: banner, icase: FALSE ) ){
				if( ContainsString( os_info[2], "RHEL" ) ){
					version = eregmatch( pattern: "RHEL([0-9.]+)", string: os_info[2] );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					continue;
				}
				else {
					if( ContainsString( os_info[2], "DEB" ) ){
						version = eregmatch( pattern: "DEB([0-9.]+)", string: os_info[2] );
						if( !isnull( version[1] ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						continue;
					}
					else {
						if(ContainsString( os_info[2], "UBUNTU" )){
							version = eregmatch( pattern: "UBUNTU([0-9.]+)", string: os_info[2] );
							if( !isnull( version[1] ) ){
								version = ereg_replace( pattern: "^([0-9]{1,2})(04|10)$", string: version[1], replace: "\\1.\\2" );
								os_register_and_report( os: "Ubuntu", version: version, cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							continue;
						}
					}
				}
			}
			else {
				continue;
			}
		}
	}
	if(ContainsString( banner, " UnityMailer " )){
		os_register_and_report( os: "Cisco", cpe: "cpe:/o:cisco", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		continue;
	}
	if(ContainsString( banner, "for Windows ready" ) || ContainsString( banner, "Microsoft ESMTP MAIL Service" ) || ContainsString( banner, "ESMTP Exchange Server" ) || ContainsString( banner, "ESMTP Microsoft Exchange" ) || ContainsString( banner, "ESMTP MS Exchange" ) || ContainsString( banner, "on Windows" )){
		if( ContainsString( banner, "Microsoft Windows 2003" ) || ContainsString( banner, "Windows 2003 Server" ) ){
			os_register_and_report( os: "Microsoft Windows Server 2003", cpe: "cpe:/o:microsoft:windows_server_2003", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
		}
		else {
			if( ContainsString( banner, "Windows 2000" ) ){
				os_register_and_report( os: "Microsoft Windows 2000", cpe: "cpe:/o:microsoft:windows_2000", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			else {
				os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
		}
		continue;
	}
	if(IsMatchRegexp( banner, "ArGoSoft Mail Server" )){
		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
		continue;
	}
	if(banner == "220 ESMTP IMSVA"){
		os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		continue;
	}
	if(ContainsString( banner, "Kerio Connect" ) || ContainsString( banner, "Kerio MailServer" )){
		continue;
	}
	if(IsMatchRegexp( banner, "^220.*SonicWall " )){
		continue;
	}
	os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "smtp_banner", port: port );
}
ports = imap_get_ports();
banner_type = "IMAP banner";
for port in ports {
	banner = imap_get_banner( port: port );
	if(!banner){
		continue;
	}
	if(ContainsString( banner, "IMAP4rev1" ) || ContainsString( banner, "IMAP server" ) || ContainsString( banner, "ImapServer" ) || ContainsString( banner, "IMAP4 Service" ) || ContainsString( banner, " IMAP4 " )){
		if(banner == "* OK IMAPrev1"){
			continue;
		}
		if(ContainsString( banner, "Xpressions" ) && ContainsString( banner, "(WIN-NT)" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			continue;
		}
		if(ContainsString( banner, "MDaemon" )){
			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			continue;
		}
		if(ContainsString( banner, "UMSS IMAP4rev1 Server" )){
			os_register_and_report( os: "Cisco", cpe: "cpe:/o:cisco", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(Ubuntu)" ) || ContainsString( banner, " ubuntu " ) || ( ContainsString( banner, "-Debian-" ) && ContainsString( banner, "ubuntu" ) )){
			os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "-Debian-" ) || ContainsString( banner, "(Debian" )){
			if( ContainsString( banner, "sarge" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "lenny" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "squeeze" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "deb7" ) || ContainsString( banner, "wheezy" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							if( ContainsString( banner, "deb8" ) ){
								os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
						}
					}
				}
			}
			continue;
		}
		if(ContainsString( banner, "-Gentoo server ready" )){
			os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(FreeBSD" )){
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "-Mageia-" )){
			version = eregmatch( pattern: "\\.mga([0-9]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Mageia", version: version[1], cpe: "cpe:/o:mageia:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Mageia", cpe: "cpe:/o:mageia:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "-Mandriva-" )){
			version = eregmatch( pattern: "mdv([0-9.]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Mandriva", version: version[1], cpe: "cpe:/o:mandriva:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Mandriva", cpe: "cpe:/o:mandriva:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "Welcome to the MANDRAKE IMAP server" ) || ContainsString( banner, "-Mandrake-" )){
			os_register_and_report( os: "Mandrake", cpe: "cpe:/o:mandrakesoft:mandrake_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "(Slackware" )){
			os_register_and_report( os: "Slackware", cpe: "cpe:/o:slackware:slackware_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if( ContainsString( banner, "\"os\" \"Linux\"" ) || ContainsString( banner, "\"os\", \"Linux\"" ) ){
			version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
			if( !isnull( version[2] ) ){
				os_register_and_report( os: "Linux", version: version[2], cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		else {
			if( ContainsString( banner, "SUSE Linux Enterprise Server" ) ){
				version = eregmatch( pattern: "SUSE Linux Enterprise Server ([0-9.]+)", string: banner );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "SUSE Linux Enterprise Server", version: version[1], cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "SUSE Linux Enterprise Server", cpe: "cpe:/o:suse:linux_enterprise_server", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				continue;
			}
			else {
				if( ContainsString( banner, "\"centos\"" ) ){
					version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
					if( !isnull( version[2] ) ){
						os_register_and_report( os: "CentOS", version: version[2], cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					continue;
				}
				else {
					if( ContainsString( banner, "CentOS release" ) ){
						version = eregmatch( pattern: "CentOS release ([0-9.]+)", string: banner );
						if( !isnull( version[1] ) ){
							os_register_and_report( os: "CentOS", version: version[1], cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						continue;
					}
					else {
						if( ContainsString( banner, "Red Hat Enterprise Linux" ) ){
							version = eregmatch( pattern: "Red Hat Enterprise Linux (Server|ES|AS|Client) release ([0-9.]+)", string: banner );
							if( !isnull( version[2] ) ){
								os_register_and_report( os: "Red Hat Enterprise Linux " + version[1], version: version[2], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							continue;
						}
						else {
							if( ContainsString( banner, "\"OpenBSD\"" ) ){
								version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
								if( !isnull( version[2] ) ){
									os_register_and_report( os: "OpenBSD", version: version[2], cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								else {
									os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								}
								continue;
							}
							else {
								if( ContainsString( banner, "\"FreeBSD\"" ) ){
									version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
									if( !isnull( version[2] ) ){
										os_register_and_report( os: "FreeBSD", version: version[2], cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									else {
										os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									}
									continue;
								}
								else {
									if( ContainsString( banner, "\"NetBSD\"" ) ){
										version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
										if( !isnull( version[2] ) ){
											os_register_and_report( os: "NetBSD", version: version[2], cpe: "cpe:/o:netbsd:netbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										else {
											os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										}
										continue;
									}
									else {
										if( ContainsString( banner, "\"SunOS\"" ) ){
											version = eregmatch( pattern: "\"os-version\"(, | )\"([0-9.]+)", string: banner );
											if( !isnull( version[2] ) ){
												os_register_and_report( os: "SunOS", version: version[2], cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											else {
												os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											}
											continue;
										}
										else {
											if( ContainsString( banner, "(\"NAME\" \"Zimbra\"" ) ){
												os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												continue;
											}
											else {
												if(ContainsString( banner, " Dovecot ready." )){
													os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
													continue;
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if(ContainsString( banner, " IceWarp " )){
			if( os_info = eregmatch( pattern: "IceWarp ([^ ]+) ([^ ]+) ([^ ]+) IMAP4rev1 ", string: banner, icase: FALSE ) ){
				if( ContainsString( os_info[2], "RHEL" ) ){
					version = eregmatch( pattern: "RHEL([0-9.]+)", string: os_info[2] );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					continue;
				}
				else {
					if( ContainsString( os_info[2], "DEB" ) ){
						version = eregmatch( pattern: "DEB([0-9.]+)", string: os_info[2] );
						if( !isnull( version[1] ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						continue;
					}
					else {
						if(ContainsString( os_info[2], "UBUNTU" )){
							version = eregmatch( pattern: "UBUNTU([0-9.]+)", string: os_info[2] );
							if( !isnull( version[1] ) ){
								version = ereg_replace( pattern: "^([0-9]{1,2})(04|10)$", string: version[1], replace: "\\1.\\2" );
								os_register_and_report( os: "Ubuntu", version: version, cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
							else {
								os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							}
						}
					}
				}
			}
			else {
				continue;
			}
		}
	}
	if(ContainsString( banner, "The Microsoft Exchange IMAP4 service is ready" ) || ContainsString( banner, "Microsoft Exchange Server" ) || ContainsString( banner, "for Windows ready" ) || ( ContainsString( banner, "service is ready" ) && ( ContainsString( banner, "(Windows/x64)" ) || ContainsString( banner, "(Windows/x86)" ) ) ) || ContainsString( banner, "Winmail Mail Server" )){
		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
		continue;
	}
	if(ContainsString( banner, "Kerio Connect" ) || ContainsString( banner, "Kerio MailServer" )){
		continue;
	}
	os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "imap_banner", port: port );
}
port = pop3_get_port( default: 110 );
banner = pop3_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(banner == "+OK POP3 ready" || banner == "+OK POP3"){
	exit( 0 );
}
banner_type = "POP3 banner";
if(ContainsString( banner, "Cyrus POP3" ) || ContainsString( banner, "Dovecot" ) || ContainsString( banner, "POP3 Server" ) || ContainsString( banner, "Mail Server" ) || ContainsString( banner, "POP3 server" ) || ContainsString( banner, " POP3 " )){
	if(ContainsString( banner, "(Ubuntu)" ) || ContainsString( banner, "ubuntu" )){
		os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "-Debian-" ) || ContainsString( banner, "(Debian" )){
		if( ContainsString( banner, "+sarge" ) ){
			os_register_and_report( os: "Debian GNU/Linux", version: "3.1", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		}
		else {
			if( ContainsString( banner, "+lenny" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "+squeeze" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "deb7" ) || ContainsString( banner, "wheezy" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						if( ContainsString( banner, "deb8" ) ){
							os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
					}
				}
			}
		}
		exit( 0 );
	}
	if(ContainsString( banner, "-Gentoo server ready" )){
		os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "-Red Hat" )){
		os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "-FreeBSD" )){
		os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "-Fedora-" )){
		os_register_and_report( os: "Fedora", cpe: "cpe:/o:fedoraproject:fedora", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "-Mandriva-" )){
		os_register_and_report( os: "Mandriva", cpe: "cpe:/o:mandriva:linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "Welcome to the MANDRAKE POP3 server" ) || ContainsString( banner, "-Mandrake-" )){
		os_register_and_report( os: "Mandrake", cpe: "cpe:/o:mandrakesoft:mandrake_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "(Slackware" )){
		os_register_and_report( os: "Slackware", cpe: "cpe:/o:slackware:slackware_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "Zimbra POP3 server ready" )){
		os_register_and_report( os: "Linux", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "+OK Dovecot ready." ) || ContainsString( banner, "* ID (\"name\" \"Dovecot\")" ) || ContainsString( banner, "+OK Dovecot DA ready." )){
		os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, " IceWarp " )){
		if( os_info = eregmatch( pattern: "IceWarp ([^ ]+) ([^ ]+) ([^ ]+) POP3 ", string: banner, icase: FALSE ) ){
			if( ContainsString( os_info[2], "RHEL" ) ){
				version = eregmatch( pattern: "RHEL([0-9.]+)", string: os_info[2] );
				if( !isnull( version[1] ) ){
					os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				exit( 0 );
			}
			else {
				if( ContainsString( os_info[2], "DEB" ) ){
					version = eregmatch( pattern: "DEB([0-9.]+)", string: os_info[2] );
					if( !isnull( version[1] ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: version[1], cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					exit( 0 );
				}
				else {
					if(ContainsString( os_info[2], "UBUNTU" )){
						version = eregmatch( pattern: "UBUNTU([0-9.]+)", string: os_info[2] );
						if( !isnull( version[1] ) ){
							version = ereg_replace( pattern: "^([0-9]{1,2})(04|10)$", string: version[1], replace: "\\1.\\2" );
							os_register_and_report( os: "Ubuntu", version: version, cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						else {
							os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						}
						exit( 0 );
					}
				}
			}
		}
		else {
			exit( 0 );
		}
	}
}
if(ContainsString( banner, "Microsoft Windows POP3 Service Version" ) || ContainsString( banner, "for Windows" ) || ContainsString( banner, "The Microsoft Exchange POP3 service is ready." ) || ContainsString( banner, "Microsoft Exchange Server" ) || ContainsString( banner, "Microsoft Exchange POP3-Server" ) || ContainsString( banner, "Winmail Mail Server" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "ArGoSoft Mail Server" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(IsMatchRegexp( banner, "MDaemon" )){
	os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: banner_type, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
	exit( 0 );
}
if(ContainsString( banner, "Kerio Connect" ) || ContainsString( banner, "Kerio MailServer" )){
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: banner_type, banner_type_short: "pop3_banner", port: port );
exit( 0 );

