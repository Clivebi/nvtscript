if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843752" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2017-2862", "CVE-2017-2870", "CVE-2017-6311" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-08 02:29:00 +0000 (Wed, 08 Nov 2017)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:15:13 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for gdk-pixbuf USN-3418-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3418-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3418-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the USN-3418-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GDK-PixBuf library did not properly handle
certain jpeg images. If an user or automated system were tricked into
opening a specially crafted jpeg file, a remote attacker could use this
flaw to cause GDK-PixBuf to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2017-2862)

It was discovered that the GDK-PixBuf library did not properly handle
certain tiff images. If an user or automated system were tricked into
opening a specially crafted tiff file, a remote attacker could use this
flaw to cause GDK-PixBuf to crash, resulting in a denial of service, or
possibly execute arbitrary code. (CVE-2017-2870)

Ariel Zelivansky discovered that the GDK-PixBuf library did not
properly handle printing certain error messages. If an user or
automated system were tricked into opening a specially crafted image
file, a remote attacker could use this flaw to cause GDK-PixBuf to
crash, resulting in a denial of service. (CVE-2017-6311)" );
	script_tag( name: "affected", value: "gdk-pixbuf on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.30.7-0ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.36.5-3ubuntu0.2", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.32.2-1ubuntu1.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

