if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841803" );
	script_version( "2020-08-11T09:13:39+0000" );
	script_tag( name: "last_modification", value: "2020-08-11 09:13:39 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-05 11:26:36 +0530 (Mon, 05 May 2014)" );
	script_cve_id( "CVE-2014-1518", "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531", "CVE-2014-1532" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Ubuntu Update for thunderbird USN-2189-1" );
	script_tag( name: "affected", value: "thunderbird on Ubuntu 14.04 LTS,
  Ubuntu 13.10,
  Ubuntu 12.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "insight", value: "Bobby Holley, Carsten Book, Christoph Diehl, Gary Kwong, Jan
de Mooij, Jesse Ruderman, Nathan Froyd and Christian Holler discovered multiple
memory safety issues in Thunderbird. If a user were tricked in to opening
a specially crafted message with scripting enabled, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-1518)

Abhishek Arya discovered an out of bounds read when decoding JPG images.
An attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2014-1523)

Abhishek Arya discovered a buffer overflow when a script uses a non-XBL
object as an XBL object. If a user had enabled scripting, an attacker
could potentially exploit this to execute arbitrary code with the
privileges of the user invoking Thunderbird. (CVE-2014-1524)

Mariusz Mlynski discovered that sites with notification permissions can
run script in a privileged context in some circumstances. If a user had
enabled scripting, an attacker could exploit this to execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2014-1529)

It was discovered that browser history navigations could be used to load
a site with the addressbar displaying the wrong address. If a user had
enabled scripting, an attacker could potentially exploit this to conduct
cross-site scripting or phishing attacks. (CVE-2014-1530)

A use-after-free was discovered when resizing images in some
circumstances. If a user had enabled scripting, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2014-1531)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free during
host resolution in some circumstances. An attacker could potentially
exploit this to cause a denial of service via application crash or execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2014-1532)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2189-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2189-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|13\\.10|12\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:24.5.0+build1-0ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:24.5.0+build1-0ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU13.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:24.5.0+build1-0ubuntu0.13.10.1", rls: "UBUNTU13.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.10"){
	if(( res = isdpkgvuln( pkg: "thunderbird", ver: "1:24.5.0+build1-0ubuntu0.12.10.1", rls: "UBUNTU12.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

