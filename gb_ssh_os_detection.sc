if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105586" );
	script_version( "2021-06-18T06:50:09+0000" );
	script_tag( name: "last_modification", value: "2021-06-18 06:50:09 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-03-23 14:28:40 +0100 (Wed, 23 Mar 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_tag( name: "summary", value: "SSH banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (SSH)";
BANNER_TYPE = "SSH banner";
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner || banner == "" || isnull( banner )){
	exit( 0 );
}
login_banner = ssh_get_login_banner( port: port );
if(egrep( pattern: "^SSH-([0-9.]+)-dropbear[_-]([0-9.]+)$", string: banner ) || banner == "SSH-2.0-dropbear"){
	exit( 0 );
}
if(IsMatchRegexp( banner, "^SSH-2.0-libssh[_-][0-9.]+$" ) || banner == "SSH-2.0-libssh"){
	exit( 0 );
}
if(banner == "SSH-2.0-SSH_2.0"){
	exit( 0 );
}
if(egrep( pattern: "^SSH-2\\.0-RomSShell_[0-9.]+$", string: banner ) || banner == "SSH-2.0-RomSShell"){
	exit( 0 );
}
if(banner == "SSH-2.0-Mocana SSH" || egrep( pattern: "^SSH-2\\.0-Mocana SSH [0-9.]+$", string: banner )){
	exit( 0 );
}
if(egrep( pattern: "^SSH-1\\.99-OpenSSH_[0-9.p]+$", string: banner ) || egrep( pattern: "^SSH-2\\.0-OpenSSH_[0-9.p]+-FIPS_hpn[0-9v]+$", string: banner ) || egrep( pattern: "^SSH-2\\.0-OpenSSH_[0-9.p]+(\\-FIPS\\(capable\\))?$", string: banner ) || banner == "SSH-2.0-OpenSSH" || banner == "SSH-2.0-OpenSSH_"){
	exit( 0 );
}
if(banner == "SSH-2.0-ROSSSH"){
	exit( 0 );
}
if(egrep( pattern: "^SSH-2\\.0-SSHD(-(UNKNOWN|SERVER|CORE)(-[0-9.]+)?(-SNAPSHOT)?)?$", string: banner )){
	exit( 0 );
}
if(egrep( pattern: "^SSH-2.0-OpenSSH_[0-9.]+ Unknown$", string: banner )){
	exit( 0 );
}
if(egrep( pattern: "^SSH-2.0-[^ ]+ PKIX($|\\[)", string: banner )){
	exit( 0 );
}
if( ContainsString( tolower( banner ), "ubuntu" ) ){
	if(ContainsString( banner, "SSH-2.0-OpenSSH_3.8.1p1 Debian 1:3.8.1p1-11ubuntu3" )){
		os_register_and_report( os: "Ubuntu", version: "4.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_3.9p1 Debian-1ubuntu2" )){
		os_register_and_report( os: "Ubuntu", version: "5.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.1p1 Debian-7ubuntu4" )){
		os_register_and_report( os: "Ubuntu", version: "5.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.2p1 Debian-7ubuntu3" )){
		os_register_and_report( os: "Ubuntu", version: "6.06", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.3p2 Debian-5ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "6.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.3p2 Debian-8ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "7.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.6p1 Debian-5ubuntu0" )){
		os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "8.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.1p1 Debian-3ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "8.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.1p1 Debian-5ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "9.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.1p1 Debian-6ubuntu2" )){
		os_register_and_report( os: "Ubuntu", version: "9.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu3" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu4" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu5" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu6" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu7" )){
		os_register_and_report( os: "Ubuntu", version: "10.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu3" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu4" ) || ContainsString( banner, "SSH-2.0-OpenSSH_5.5p1 Debian-4ubuntu5" )){
		os_register_and_report( os: "Ubuntu", version: "10.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.8p1 Debian-1ubuntu3" )){
		os_register_and_report( os: "Ubuntu", version: "11.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.8p1 Debian-7ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "11.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu" )){
		os_register_and_report( os: "Ubuntu", version: "12.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.0p1 Debian-3ubuntu" )){
		os_register_and_report( os: "Ubuntu", version: "12.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.1p1 Debian-3ubuntu" )){
		os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.2p2 Ubuntu-6" )){
		os_register_and_report( os: "Ubuntu", version: "13.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.6p1 Ubuntu-2" ) || ContainsString( banner, "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2" )){
		os_register_and_report( os: "Ubuntu", version: "14.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-8" )){
		os_register_and_report( os: "Ubuntu", version: "14.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1" )){
		os_register_and_report( os: "Ubuntu", version: "15.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_6.9p1 Ubuntu-2" )){
		os_register_and_report( os: "Ubuntu", version: "15.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4" )){
		os_register_and_report( os: "Ubuntu", version: "16.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.3p1 Ubuntu-1" )){
		os_register_and_report( os: "Ubuntu", version: "16.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10" )){
		os_register_and_report( os: "Ubuntu", version: "17.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.5p1 Ubuntu-10" )){
		os_register_and_report( os: "Ubuntu", version: "17.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4" )){
		os_register_and_report( os: "Ubuntu", version: "18.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.7p1 Ubuntu-4" )){
		os_register_and_report( os: "Ubuntu", version: "18.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10" )){
		os_register_and_report( os: "Ubuntu", version: "19.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_8.0p1 Ubuntu-6" )){
		os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(ContainsString( banner, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4" )){
		os_register_and_report( os: "Ubuntu", version: "20.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	exit( 0 );
}
else {
	if( ContainsString( banner, "Debian" ) || ContainsString( banner, "Raspbian" ) ){
		if(ContainsString( banner, "SSH-2.0-OpenSSH_4.6p1 Debian-5build1" )){
			os_register_and_report( os: "Ubuntu", version: "7.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_6.1p1 Debian-4" )){
			os_register_and_report( os: "Ubuntu", version: "13.04", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_5.1p1 Debian" )){
			os_register_and_report( os: "Debian GNU/Linux", version: "5.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_5.5p1 Debian-6" )){
			os_register_and_report( os: "Debian GNU/Linux", version: "6.0", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_6.0p1 Debian-4" ) || ( ContainsString( banner, "~bpo7" ) && ContainsString( banner, "SSH-2.0-OpenSSH_" ) )){
			os_register_and_report( os: "Debian GNU/Linux", version: "7", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_6.7p1 Debian-5" ) || ContainsString( banner, "SSH-2.0-OpenSSH_6.7p1 Raspbian-5" ) || ( ContainsString( banner, "~bpo8" ) && ContainsString( banner, "SSH-2.0-OpenSSH_" ) )){
			os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_7.4p1 Debian-10" ) || ContainsString( banner, "SSH-2.0-OpenSSH_7.4p1 Raspbian-10" ) || ( ContainsString( banner, "~bpo9" ) && ContainsString( banner, "SSH-2.0-OpenSSH_" ) )){
			os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		if(ContainsString( banner, "SSH-2.0-OpenSSH_7.9p1 Debian-10" ) || ContainsString( banner, "SSH-2.0-OpenSSH_7.9p1 Raspbian-10" ) || ( ContainsString( banner, "~bpo10" ) && ContainsString( banner, "SSH-2.0-OpenSSH_" ) )){
			os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	else {
		if( ContainsString( banner, "FreeBSD" ) ){
			if(ContainsString( banner, "SSH-2.0-OpenSSH_4.5p1 FreeBSD-20061110" )){
				os_register_and_report( os: "FreeBSD", version: "7.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_5.1p1 FreeBSD-20080901" )){
				os_register_and_report( os: "FreeBSD", version: "7.2", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_5.2p1 FreeBSD-20090522" )){
				os_register_and_report( os: "FreeBSD", version: "8.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_5.4p1 FreeBSD-20100308" )){
				os_register_and_report( os: "FreeBSD", version: "8.1", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_5.8p2_hpn13v11 FreeBSD-20110503" )){
				os_register_and_report( os: "FreeBSD", version: "9.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_6.4_hpn13v11 FreeBSD-20131111" )){
				os_register_and_report( os: "FreeBSD", version: "10.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_7.2 FreeBSD-20160310" )){
				os_register_and_report( os: "FreeBSD", version: "11.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_7.2 FreeBSD-20161230" )){
				os_register_and_report( os: "FreeBSD", version: "11.1", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_7.5 FreeBSD-20170903" )){
				os_register_and_report( os: "FreeBSD", version: "11.2", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			if(ContainsString( banner, "SSH-2.0-OpenSSH_7.8 FreeBSD-20180909" )){
				os_register_and_report( os: "FreeBSD", version: "12.0", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			exit( 0 );
		}
		else {
			if( ContainsString( banner, "OpenBSD" ) ){
				os_register_and_report( os: "OpenBSD", cpe: "cpe:/o:openbsd:openbsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				exit( 0 );
			}
			else {
				if( ContainsString( banner, "NetBSD" ) ){
					os_register_and_report( os: "NetBSD", cpe: "cpe:/o:netbsd:netbsd", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					exit( 0 );
				}
				else {
					if( ContainsString( banner, "CISCO_WLC" ) ){
						os_register_and_report( os: "Cisco Wireless Lan Controller", cpe: "cpe:/o:cisco:wireless_lan_controller", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
						exit( 0 );
					}
					else {
						if( IsMatchRegexp( banner, "^SSH-[0-9.]+-Cisco-[0-9.]+" ) ){
							os_register_and_report( os: "Cisco IOS", cpe: "cpe:/o:cisco:ios", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
							exit( 0 );
						}
						else {
							if( eregmatch( string: banner, pattern: "(cisco|FIPS User Access Verification)", icase: TRUE ) || ContainsString( login_banner, "Cisco Systems, Inc. All rights Reserved" ) ){
								os_register_and_report( os: "Cisco", cpe: "cpe:/o:cisco", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
								exit( 0 );
							}
							else {
								if( IsMatchRegexp( banner, "SSH-[0-9.]+-Sun_SSH" ) ){
									os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
									exit( 0 );
								}
								else {
									if( ContainsString( banner, "SSH-2.0-NetScreen" ) ){
										os_register_and_report( os: "NetScreen ScreenOS", cpe: "cpe:/o:juniper:netscreen_screenos", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
										exit( 0 );
									}
									else {
										if( eregmatch( string: banner, pattern: "SSH-2.0-xxxxxxx|FortiSSH" ) ){
											os_register_and_report( os: "FortiOS", cpe: "cpe:/o:fortinet:fortios", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
											exit( 0 );
										}
										else {
											if( ContainsString( banner, "OpenVMS" ) ){
												os_register_and_report( os: "OpenVMS", cpe: "cpe:/o:hp:openvms", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
												exit( 0 );
											}
											else {
												if( ContainsString( banner, "SSH-2.0-MS_" ) ){
													os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows_10:-:-:iot", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
													exit( 0 );
												}
												else {
													if( ContainsString( banner, "SSH-2.0-WeOnlyDo" ) ){
														os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
														exit( 0 );
													}
													else {
														if( ContainsString( banner, "SSH-2.0-mpSSH_" ) ){
															os_register_and_report( os: "HP iLO", cpe: "cpe:/o:hp:integrated_lights-out", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
															exit( 0 );
														}
														else {
															if( ContainsString( banner, "SSH-2.0-Data ONTAP SSH" ) ){
																os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																exit( 0 );
															}
															else {
																if( ContainsString( banner, "SSH-2.0-moxa_" ) ){
																	os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																	exit( 0 );
																}
																else {
																	if( ContainsString( banner, "Network ConfigManager SCP Server" ) ){
																		os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																		exit( 0 );
																	}
																	else {
																		if( ContainsString( banner, "OpenSSH_for_Windows" ) ){
																			os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																			exit( 0 );
																		}
																		else {
																			if( egrep( pattern: "SSH.+Data ONTAP SSH", string: banner ) ){
																				os_register_and_report( os: "NetApp Data ONTAP", cpe: "cpe:/o:netapp:data_ontap", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																				exit( 0 );
																			}
																			else {
																				if( egrep( pattern: "SSH.+-Zyxel SSH server", string: banner ) ){
																					os_register_and_report( os: "Zyxel USG Firmware", cpe: "cpe:/o:zyxel:usg_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																					exit( 0 );
																				}
																				else {
																					if( egrep( pattern: "SSH.+Greenbone OS", string: banner ) || ContainsString( login_banner, "Welcome to Greenbone OS" ) ){
																						os_register_and_report( os: "Greenbone OS (GOS)", cpe: "cpe:/o:greenbone:greenbone_os", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																						exit( 0 );
																					}
																					else {
																						if( banner == "SSH-2.0--" || ContainsString( banner, "SSH-2.0-HUAWEI-" ) || banner == "SSH-1.99--" ){
																							os_register_and_report( os: "Huawei Unknown Model Versatile Routing Platform (VRP) network device Firmware", cpe: "cpe:/o:huawei:vrp_firmware", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																							exit( 0 );
																						}
																						else {
																							if( ContainsString( banner, "SSH-2.0-NOS-SSH" ) ){
																								os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
																								exit( 0 );
																							}
																							else {
																								if(ContainsString( banner, "WinSSHD" )){
																									os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
																									exit( 0 );
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
		}
	}
}
if(IsMatchRegexp( banner, "OpenSSL.+-rhel" )){
	version = eregmatch( pattern: "OpenSSL.+-rhel([0-9]+)", string: banner, icase: FALSE );
	if( !isnull( version[1] ) ) {
		os_register_and_report( os: "Red Hat Enterprise Linux", version: version[1], cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	else {
		os_register_and_report( os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", banner_type: BANNER_TYPE, port: port, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
	}
	exit( 0 );
}
os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "ssh_banner", port: port );
exit( 0 );

