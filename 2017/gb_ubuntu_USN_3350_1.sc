if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843239" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-14 15:54:55 +0530 (Fri, 14 Jul 2017)" );
	script_cve_id( "CVE-2017-2820", "CVE-2017-7511", "CVE-2017-7515", "CVE-2017-9083", "CVE-2017-9406", "CVE-2017-9408", "CVE-2017-9775" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-17 15:28:00 +0000 (Mon, 17 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for poppler USN-3350-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Aleksandar Nikolic discovered that poppler
  incorrectly handled JPEG 2000 images. If a user or automated system were tricked
  into opening a crafted PDF file, an attacker could cause a denial of service or
  possibly execute arbitrary code with privileges of the user invoking the
  program. (CVE-2017-2820) Jiaqi Peng discovered that the poppler pdfunite tool
  incorrectly parsed certain malformed PDF documents. If a user or automated
  system were tricked into opening a crafted PDF file, an attacker could cause
  poppler to crash, resulting in a denial of service. (CVE-2017-7511) It was
  discovered that the poppler pdfunite tool incorrectly parsed certain malformed
  PDF documents. If a user or automated system were tricked into opening a crafted
  PDF file, an attacker could cause poppler to hang, resulting in a denial of
  service. (CVE-2017-7515) It was discovered that poppler incorrectly handled JPEG
  2000 images. If a user or automated system were tricked into opening a crafted
  PDF file, an attacker could cause cause poppler to crash, resulting in a denial
  of service. (CVE-2017-9083) It was discovered that poppler incorrectly handled
  memory when processing PDF documents. If a user or automated system were tricked
  into opening a crafted PDF file, an attacker could cause poppler to consume
  resources, resulting in a denial of service. (CVE-2017-9406, CVE-2017-9408)
  Alberto Garcia, Francisco Oca, and Suleman Ali discovered that the poppler
  pdftocairo tool incorrectly parsed certain malformed PDF documents. If a user or
  automated system were tricked into opening a crafted PDF file, an attacker could
  cause poppler to crash, resulting in a denial of service. (CVE-2017-9775)" );
	script_tag( name: "affected", value: "poppler on Ubuntu 17.04,
  Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3350-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3350-1/" );
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
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0:i386", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0:amd64", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:i386", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:amd64", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:i386", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:amd64", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:i386", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:amd64", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler44:i386", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler44:amd64", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.24.5-2ubuntu4.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0v5:i386", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0v5:amd64", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:i386", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:amd64", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:i386", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:amd64", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:i386", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:amd64", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler64:i386", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler64:amd64", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.48.0-2ubuntu2.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0v5:i386", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0v5:amd64", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:i386", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:amd64", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:i386", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:amd64", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:i386", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:amd64", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler61:i386", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler61:amd64", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.44.0-3ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0:i386", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-cpp0:amd64", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:i386", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-glib8:amd64", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:i386", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt4-4:amd64", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:i386", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler-qt5-1:amd64", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler58:i386", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libpoppler58:amd64", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "poppler-utils", ver: "0.41.0-0ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

