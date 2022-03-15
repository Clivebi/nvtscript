if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842467" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-30 07:08:03 +0200 (Wed, 30 Sep 2015)" );
	script_cve_id( "CVE-2015-5697", "CVE-2015-6252" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for linux-lts-vivid USN-2751-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-lts-vivid'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Benjamin Randazzo discovered an information leak in the md (multiple
device) driver when the bitmap_info.file is disabled. A local privileged
attacker could use this to obtain sensitive information from the kernel.
(CVE-2015-5697)

Marc-Andr&#233  Lureau discovered that the vhost driver did not properly
release the userspace provided log file descriptor. A privileged attacker
could use this to cause a denial of service (resource exhaustion).
(CVE-2015-6252)" );
	script_tag( name: "affected", value: "linux-lts-vivid on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2751-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2751-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-generic", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-generic-lpae", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-lowlatency", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-powerpc-e500mc", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-powerpc-smp", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-powerpc64-emb", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "linux-image-3.19.0-30-powerpc64-smp", ver: "3.19.0-30.33~14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

