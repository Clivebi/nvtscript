if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842411" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-18 06:50:54 +0200 (Tue, 18 Aug 2015)" );
	script_cve_id( "CVE-2015-3212", "CVE-2015-5364", "CVE-2015-5366" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux USN-2713-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Marcelo Ricardo Leitner discovered a race
condition in the Linux kernel's SCTP address configuration lists when using
Address Configuration Change (ASCONF) options on a socket. An unprivileged local
user could exploit this flaw to cause a denial of service (system crash).
(CVE-2015-3212)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker could exploit this flaw to cause a denial of
service using a flood of UDP packets with invalid checksums.
(CVE-2015-5364)

A flaw was discovered in how the Linux kernel handles invalid UDP
checksums. A remote attacker can cause a denial of service against
applications that use epoll by injecting a single packet with an invalid
checksum. (CVE-2015-5366)" );
	script_tag( name: "affected", value: "linux on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2713-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2713-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-generic", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-generic-pae", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-highbank", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-omap", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-powerpc-smp", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-powerpc64-smp", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.2.0-89-virtual", ver: "3.2.0-89.127", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

