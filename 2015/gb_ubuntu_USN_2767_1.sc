if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842486" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-14 08:04:53 +0200 (Wed, 14 Oct 2015)" );
	script_cve_id( "CVE-2015-7673", "CVE-2015-7674" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for gdk-pixbuf USN-2767-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Gustavo Grieco discovered that the GDK-PixBuf library did not properly
handle scaling tga image files, leading to a heap overflow. If a
user or automated system were tricked into opening a tga image file,
a remote attacker could use this flaw to cause GDK-PixBuf to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7673)

Gustavo Grieco discovered that the GDK-PixBuf library contained
an integer overflow when handling certain GIF images. If a user
or automated system were tricked into opening a GIF image file,
a remote attacker could use this flaw to cause GDK-PixBuf to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7674)" );
	script_tag( name: "affected", value: "gdk-pixbuf on Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2767-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2767-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS)" );
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
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.31.3-1ubuntu0.2", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.30.7-0ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.26.1-1ubuntu1.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

