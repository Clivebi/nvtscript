if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844857" );
	script_version( "2021-03-17T09:33:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-17 09:33:35 +0000 (Wed, 17 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-09 04:00:20 +0000 (Tue, 09 Mar 2021)" );
	script_name( "Ubuntu: Security Advisory for gnome-autoar (USN-4733-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU20\\.04 LTS|UBUNTU18\\.04 LTS|UBUNTU20\\.10)" );
	script_xref( name: "Advisory-ID", value: "USN-4733-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-March/005922.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnome-autoar'
  package(s) announced via the USN-4733-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4733-1 fixed a vulnerability in GNOME Autoar. The upstream fix
introduced a regression when extracting archives containing directories.
This update fixes the problem.

Original advisory details:

Yiit Can Ylmaz discovered that GNOME Autoar could extract files outside
of the intended directory. If a user were tricked into extracting a
specially crafted archive, a remote attacker could create files in
arbitrary locations, possibly leading to code execution." );
	script_tag( name: "affected", value: "'gnome-autoar' package(s) on Ubuntu 20.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS." );
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
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-0-0", ver: "0.2.3-2ubuntu0.2", rls: "UBUNTU20.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-gtk-0-0", ver: "0.2.3-2ubuntu0.2", rls: "UBUNTU20.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-0-0", ver: "0.2.3-1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-gtk-0-0", ver: "0.2.3-1ubuntu0.2", rls: "UBUNTU18.04 LTS" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-0-0", ver: "0.2.4-2ubuntu0.2", rls: "UBUNTU20.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgnome-autoar-gtk-0-0", ver: "0.2.4-2ubuntu0.2", rls: "UBUNTU20.10" ) )){
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

