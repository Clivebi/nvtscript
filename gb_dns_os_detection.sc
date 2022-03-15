if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108014" );
	script_version( "2021-10-06T05:47:37+0000" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "creation_date", value: "2016-11-03 14:13:48 +0100 (Thu, 03 Nov 2016)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (DNS)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "dns_server_tcp.sc", "dns_server.sc" );
	script_mandatory_keys( "DNS/identified" );
	script_tag( name: "summary", value: "DNS banner based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (DNS)";
BANNER_TYPE = "DNS server banner";
for proto in make_list( "udp",
	 "tcp" ) {
	banners = get_kb_list( "DNS/" + proto + "/version_request/*" );
	if(!banners){
		continue;
	}
	for key in keys( banners ) {
		kb_key = "DNS/" + proto + "/version_request/";
		port = int( key - kb_key );
		banner = banners[key];
		if(ContainsString( banner, "Microsoft" ) || ContainsString( banner, "Windows" )){
			if( ContainsString( banner, "Windows 2008 DNS Server Ready" ) ){
				os_register_and_report( os: "Microsoft Windows 2008 Server", cpe: "cpe:/o:microsoft:windows_server_2008", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			else {
				os_register_and_report( os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "windows" );
			}
			continue;
		}
		if(ContainsString( banner, "FreeBSD" )){
			os_register_and_report( os: "FreeBSD", cpe: "cpe:/o:freebsd:freebsd", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "SunOS DNS Server" )){
			os_register_and_report( os: "SunOS", cpe: "cpe:/o:sun:sunos", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "Gentoo Gnu/Linux" )){
			os_register_and_report( os: "Gentoo", cpe: "cpe:/o:gentoo:linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(IsMatchRegexp( banner, "ubuntu" )){
			if( ContainsString( banner, "9.11.5-P4-5.1ubuntu" ) ) {
				os_register_and_report( os: "Ubuntu", version: "19.10", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Ubuntu", cpe: "cpe:/o:canonical:ubuntu_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "for Fedora Linux" ) || ( ( ContainsString( banner, "PowerDNS" ) || ContainsString( banner, "jenkins@autotest.powerdns.com" ) ) && ContainsString( banner, ".fedoraproject.org" ) )){
			os_register_and_report( os: "Fedora Linux", cpe: "cpe:/o:fedoraproject:fedora", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "-SuSE" )){
			os_register_and_report( os: "SUSE Linux", cpe: "cpe:/o:novell:suse_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			continue;
		}
		if(ContainsString( banner, "-RedHat" ) && ContainsString( banner, ".fc" )){
			version = eregmatch( pattern: "\\.fc([0-9]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Fedora Linux", version: version[1], cpe: "cpe:/o:fedoraproject:fedora", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Fedora Linux", cpe: "cpe:/o:fedoraproject:fedora", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(IsMatchRegexp( banner, "-RedHat.+\\.h" )){
			version = eregmatch( pattern: "[0-9.-]+\\.h([1-9])", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "EulerOS", version: version[1], cpe: "cpe:/o:huawei:euleros", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "EulerOS", cpe: "cpe:/o:huawei:euleros", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(ContainsString( banner, "-RedHat" )){
			version = eregmatch( pattern: "\\.el([0-9]+)", string: banner );
			if( !isnull( version[1] ) ){
				os_register_and_report( os: "Redhat Linux", version: version[1], cpe: "cpe:/o:redhat:linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				os_register_and_report( os: "Redhat Linux", cpe: "cpe:/o:redhat:linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			continue;
		}
		if(( ContainsString( banner, "PowerDNS" ) || ContainsString( banner, "jenkins@autotest.powerdns.com" ) ) && ContainsString( banner, "-centos-" )){
			if( ContainsString( banner, "-centos-7" ) ){
				os_register_and_report( os: "CentOS", version: "7", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "-centos-65" ) ){
					os_register_and_report( os: "CentOS", version: "6.5", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					os_register_and_report( os: "CentOS", cpe: "cpe:/o:centos:centos", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
			}
			continue;
		}
		if(ContainsString( banner, "-Debian" ) || ( ContainsString( banner, "PowerDNS Authoritative Server" ) && ContainsString( banner, "debian.org)" ) )){
			if( ContainsString( banner, "+deb8" ) ){
				os_register_and_report( os: "Debian GNU/Linux", version: "8", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			}
			else {
				if( ContainsString( banner, "9.10.3-P4-Debian" ) || ContainsString( banner, "+deb9" ) ){
					os_register_and_report( os: "Debian GNU/Linux", version: "9", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
				}
				else {
					if( ContainsString( banner, "9.11.5-P4-5.1-Debian" ) || ContainsString( banner, "+deb10" ) ){
						os_register_and_report( os: "Debian GNU/Linux", version: "10", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
					else {
						os_register_and_report( os: "Debian GNU/Linux", cpe: "cpe:/o:debian:debian_linux", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
					}
				}
			}
			continue;
		}
		if(IsMatchRegexp( banner, "^dnsmasq" ) || IsMatchRegexp( banner, "^PowerDNS Authoritative Server" ) || IsMatchRegexp( banner, "^PowerDNS Recursor" ) || ContainsString( banner, "jenkins@autotest.powerdns.com" ) || IsMatchRegexp( banner, "^Knot DNS" )){
			os_register_and_report( os: "Linux/Unix", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, proto: proto, banner: banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
			if(banner == "dnsmasq" || egrep( pattern: "^dnsmasq-(pi-hole-)?([0-9.]+((rc|test)[0-9]+)?)$", string: banner ) || egrep( pattern: "^PowerDNS Authoritative Server ([0-9.]+)$", string: banner ) || egrep( pattern: "^PowerDNS Recursor ([0-9.]+)$", string: banner ) || egrep( pattern: "^Knot DNS ([0-9.]+)$", string: banner )){
				continue;
			}
		}
		os_register_unknown_banner( banner: banner, banner_type_name: BANNER_TYPE, banner_type_short: "dns_banner", port: port, proto: proto );
	}
}
exit( 0 );

