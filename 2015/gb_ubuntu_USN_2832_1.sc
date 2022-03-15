if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842555" );
	script_version( "2020-11-24T09:37:13+0000" );
	script_tag( name: "last_modification", value: "2020-11-24 09:37:13 +0000 (Tue, 24 Nov 2020)" );
	script_tag( name: "creation_date", value: "2015-12-08 10:56:12 +0100 (Tue, 08 Dec 2015)" );
	script_cve_id( "CVE-2014-9496", "CVE-2014-9756", "CVE-2015-7805" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libsndfile USN-2832-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libsndfile'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libsndfile incorrectly
handled memory when parsing malformed files. A remote attacker could use this issue
to cause libsndfile to crash, resulting in a denial of service. This issue only
applied to Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-9496)

Joshua Rogers discovered that libsndfile incorrectly handled division when
parsing malformed files. A remote attacker could use this issue to cause
libsndfile to crash, resulting in a denial of service. (CVE-2014-9756)

Marco Romano discovered that libsndfile incorrectly handled certain
malformed AIFF files. A remote attacker could use this issue to cause
libsndfile to crash, resulting in a denial of service, or possibly execute
arbitrary code. (CVE-2015-7805)" );
	script_tag( name: "affected", value: "libsndfile on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2832-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2832-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "libsndfile1:amd64", ver: "1.0.25-9.1ubuntu0.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsndfile1:i386", ver: "1.0.25-9.1ubuntu0.15.04.1", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsndfile1:amd64", ver: "1.0.25-7ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsndfile1:i386", ver: "1.0.25-7ubuntu2.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libsndfile1", ver: "1.0.25-4ubuntu0.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libsndfile1:amd64", ver: "1.0.25-9.1ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libsndfile1:i386", ver: "1.0.25-9.1ubuntu0.15.10.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

