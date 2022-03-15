if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844589" );
	script_version( "2021-07-12T02:00:56+0000" );
	script_cve_id( "CVE-2020-15710" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-12 02:00:56 +0000 (Mon, 12 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-16 15:08:00 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-09-18 03:00:23 +0000 (Fri, 18 Sep 2020)" );
	script_name( "Ubuntu: Security Advisory for pulseaudio (USN-4519-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "4519-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-September/005628.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pulseaudio'
  package(s) announced via the USN-4519-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Ratchanan Srirattanamet discovered that an Ubuntu-specific patch caused
PulseAudio to incorrectly handle memory under certain error conditions in the
Bluez 5 module. An attacker could use this issue to cause PulseAudio to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2020-15710)" );
	script_tag( name: "affected", value: "'pulseaudio' package(s) on Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libpulse-mainloop-glib0", ver: "1:8.0-0ubuntu3.14", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpulse0", ver: "1:8.0-0ubuntu3.14", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio", ver: "1:8.0-0ubuntu3.14", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-module-bluetooth", ver: "1:8.0-0ubuntu3.14", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "pulseaudio-utils", ver: "1:8.0-0ubuntu3.14", rls: "UBUNTU16.04 LTS" ) )){
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

