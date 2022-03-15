if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1435-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840996" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "creation_date", value: "2012-05-04 10:47:56 +0530 (Fri, 04 May 2012)" );
	script_cve_id( "CVE-2012-0247", "CVE-2012-1185", "CVE-2012-0248", "CVE-2012-1186", "CVE-2012-0259", "CVE-2012-1610", "CVE-2012-1798" );
	script_xref( name: "USN", value: "1435-1" );
	script_name( "Ubuntu Update for imagemagick USN-1435-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|12\\.04 LTS|11\\.10|11\\.04)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1435-1" );
	script_tag( name: "affected", value: "imagemagick on Ubuntu 12.04 LTS,
  Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
  incorrectly handled certain ResolutionUnit tags. If a user or automated
  system using ImageMagick were tricked into opening a specially crafted
  image, an attacker could exploit this to cause a denial of service or
  possibly execute code with the privileges of the user invoking the program.
  (CVE-2012-0247, CVE-2012-1185)

  Joonas Kuorilehto and Aleksis Kauppinen discovered that ImageMagick
  incorrectly handled certain IFD structures. If a user or automated
  system using ImageMagick were tricked into opening a specially crafted
  image, an attacker could exploit this to cause a denial of service.
  (CVE-2012-0248, CVE-2012-1186)

  Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered that
  ImageMagick incorrectly handled certain JPEG EXIF tags. If a user or
  automated system using ImageMagick were tricked into opening a specially
  crafted image, an attacker could exploit this to cause a denial of service.
  (CVE-2012-0259)

  It was discovered that ImageMagick incorrectly handled certain JPEG EXIF
  tags. If a user or automated system using ImageMagick were tricked into
  opening a specially crafted image, an attacker could exploit this to cause
  a denial of service or possibly execute code with the privileges of the
  user invoking the program. (CVE-2012-1610)

  Aleksis Kauppinen, Joonas Kuorilehto and Tuomas Parttimaa discovered that
  ImageMagick incorrectly handled certain TIFF EXIF tags. If a user or
  automated system using ImageMagick were tricked into opening a specially
  crafted image, an attacker could exploit this to cause a denial of service
  or possibly execute code with the privileges of the user invoking the
  program. (CVE-2012-1798)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "imagemagick", ver: "6.5.7.8-1ubuntu1.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagick++2", ver: "6.5.7.8-1ubuntu1.2", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "imagemagick", ver: "6.6.9.7-5ubuntu3.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagick++4", ver: "6.6.9.7-5ubuntu3.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "imagemagick", ver: "6.6.0.4-3ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagick++3", ver: "6.6.0.4-3ubuntu1.1", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "imagemagick", ver: "6.6.2.6-1ubuntu4.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libmagick++3", ver: "6.6.2.6-1ubuntu4.1", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

