if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843750" );
	script_version( "2021-06-03T11:00:21+0000" );
	script_cve_id( "CVE-2017-1000422", "CVE-2017-6312", "CVE-2017-6313", "CVE-2017-6314" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-03 11:00:21 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-02 16:35:00 +0000 (Thu, 02 May 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:15:00 +0200 (Fri, 26 Oct 2018)" );
	script_name( "Ubuntu Update for gdk-pixbuf USN-3532-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.10|16\\.04 LTS)" );
	script_xref( name: "USN", value: "3532-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3532-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the USN-3532-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discoreved that GDK-PixBuf incorrectly handled certain gif
images. An attacker could use this to execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2017-1000422)

Ariel Zelivansky discovered that GDK-PixBuf incorrectly handled certain
images. An attacker could use this to cause a denial of service.
(CVE-2017-6312, CVE-2017-6313)

Ariel Zelivansky discovered that GDK-PixBuf incorrectly handled large
TIFF files. An attacker could use this to cause a denial of service.
(CVE-2017-6314)" );
	script_tag( name: "affected", value: "gdk-pixbuf on Ubuntu 17.10,
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
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.30.7-0ubuntu1.8", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.10"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.36.11-1ubuntu0.1", rls: "UBUNTU17.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.32.2-1ubuntu1.4", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

