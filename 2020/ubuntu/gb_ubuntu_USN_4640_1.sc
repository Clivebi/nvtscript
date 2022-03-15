if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844724" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-16123" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-10 14:52:00 +0000 (Thu, 10 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-11-24 04:00:40 +0000 (Tue, 24 Nov 2020)" );
	script_name( "Ubuntu: Security Advisory for pulseaudio (USN-4640-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "USN", value: "4640-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-November/005771.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pulseaudio'
  package(s) announced via the USN-4640-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "James Henstridge discovered that an Ubuntu-specific patch caused
PulseAudio to incorrectly handle snap client connections. An attacker
could possibly use this to expose sensitive information." );
	script_tag( name: "affected", value: "'pulseaudio' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU20.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpulse-mainloop-glib0", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulse0", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulsedsp", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-equalizer", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-bluetooth", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-gsettings", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-jack", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-lirc", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-raop", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-zeroconf", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-utils", ver: "1:13.99.1-1ubuntu3.8", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpulse-mainloop-glib0", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulse0", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulsedsp", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-equalizer", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-esound-compat", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-bluetooth", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-gconf", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-jack", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-lirc", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-raop", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-zeroconf", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-utils", ver: "1:11.1-1ubuntu7.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpulse-mainloop-glib0", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulse0", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulsedsp", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-esound-compat", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-bluetooth", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-droid", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-gconf", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-jack", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-lirc", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-raop", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-trust-store", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-x11", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-zeroconf", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-utils", ver: "1:8.0-0ubuntu3.15", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU20.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libpulse-mainloop-glib0", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulse0", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulsedsp", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-equalizer", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-bluetooth", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-gsettings", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-jack", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-lirc", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-raop", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-zeroconf", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-utils", ver: "1:13.99.2-1ubuntu2.1", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

