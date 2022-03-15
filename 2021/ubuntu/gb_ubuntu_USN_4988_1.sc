if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844976" );
	script_version( "2021-08-18T06:00:55+0000" );
	script_cve_id( "CVE-2017-14528", "CVE-2020-19667", "CVE-2020-25665", "CVE-2020-25666", "CVE-2020-25674", "CVE-2020-25675", "CVE-2020-25676", "CVE-2020-27750", "CVE-2020-27751", "CVE-2020-27753", "CVE-2020-27754", "CVE-2020-27755", "CVE-2020-27756", "CVE-2020-27757", "CVE-2020-27758", "CVE-2020-27759", "CVE-2020-27760", "CVE-2020-27761", "CVE-2020-27762", "CVE-2020-27763", "CVE-2020-27764", "CVE-2020-27765", "CVE-2020-27766", "CVE-2020-27767", "CVE-2020-27768", "CVE-2020-27769", "CVE-2020-27770", "CVE-2020-27771", "CVE-2020-27772", "CVE-2020-27773", "CVE-2020-27774", "CVE-2020-27775", "CVE-2020-27776", "CVE-2021-20176" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-18 06:00:55 +0000 (Wed, 18 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 20:19:00 +0000 (Wed, 24 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-06-16 03:00:30 +0000 (Wed, 16 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for imagemagick (USN-4988-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4988-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006072.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'imagemagick'
  package(s) announced via the USN-4988-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that ImageMagick incorrectly handled certain malformed
image files. If a user or automated system using ImageMagick were tricked
into opening a specially crafted image, an attacker could exploit this to
cause a denial of service or possibly execute code with the privileges of
the user invoking the program." );
	script_tag( name: "affected", value: "'imagemagick' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.10.23+dfsg-2.1ubuntu11.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.10.23+dfsg-2.1ubuntu11.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "-6.q16-8", ver: "8:6.9.10.23+dfsg-2.1ubuntu11.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-6", ver: "8:6.9.10.23+dfsg-2.1ubuntu11.4", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-6-extra", ver: "8:6.9.10.23+dfsg-2.1ubuntu11.4", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.7.4+dfsg-16ubuntu6.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.7.4+dfsg-16ubuntu6.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "-6.q16-7", ver: "8:6.9.7.4+dfsg-16ubuntu6.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3", ver: "8:6.9.7.4+dfsg-16ubuntu6.11", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-3-extra", ver: "8:6.9.7.4+dfsg-16ubuntu6.11", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.9.10.23+dfsg-2.1ubuntu13.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "imagemagick-6.q16", ver: "8:6.9.10.23+dfsg-2.1ubuntu13.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "-6.q16-8", ver: "8:6.9.10.23+dfsg-2.1ubuntu13.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-6", ver: "8:6.9.10.23+dfsg-2.1ubuntu13.3", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-6.q16-6-extra", ver: "8:6.9.10.23+dfsg-2.1ubuntu13.3", rls: "UBUNTU20.10" ) )){
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

