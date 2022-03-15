if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843182" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-25 06:50:19 +0200 (Thu, 25 May 2017)" );
	script_cve_id( "CVE-2016-9601", "CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for jbig2dec USN-3297-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jbig2dec'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Bingchang Liu discovered that jbig2dec
incorrectly handled memory when decoding malformed image files. If a user or
automated system were tricked into processing a specially crafted JBIG2 image
file, a remote attacker could cause jbig2dec to crash, resulting in a denial
of service, or possibly execute arbitrary code. This issue only applied to
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2016-9601)

It was discovered that jbig2dec incorrectly handled memory when decoding
malformed image files. If a user or automated system were tricked into
processing a specially crafted JBIG2 image file, a remote attacker could
cause jbig2dec to crash, resulting in a denial of service, or possibly
disclose sensitive information. (CVE-2017-7885)

Jiaqi Peng discovered that jbig2dec incorrectly handled memory when
decoding malformed image files. If a user or automated system were tricked
into processing a specially crafted JBIG2 image file, a remote attacker
could cause jbig2dec to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2017-7975)

Dai Ge discovered that jbig2dec incorrectly handled memory when decoding
malformed image files. If a user or automated system were tricked into
processing a specially crafted JBIG2 image file, a remote attacker could
cause jbig2dec to crash, resulting in a denial of service, or possibly
disclose sensitive information. (CVE-2017-7976)" );
	script_tag( name: "affected", value: "jbig2dec on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3297-1" );
	script_xref( name: "URL", value: "https://www.ubuntu.com/usn/usn-3297-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.10|16\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "jbig2dec", ver: "0.11+20120125-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libjbig2dec0", ver: "0.11+20120125-1ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "jbig2dec", ver: "0.13-4ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libjbig2dec0", ver: "0.13-4ubuntu0.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "jbig2dec", ver: "0.13-2ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libjbig2dec0", ver: "0.13-2ubuntu0.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "jbig2dec", ver: "0.12+20150918-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libjbig2dec0", ver: "0.12+20150918-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

