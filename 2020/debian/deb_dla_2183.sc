if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892183" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2016-9888" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-15 03:00:00 +0000 (Thu, 15 Dec 2016)" );
	script_tag( name: "creation_date", value: "2020-04-26 03:00:04 +0000 (Sun, 26 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for libgsf (DLA-2183-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2183-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libgsf'
  package(s) announced via the DLA-2183-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that there was a null pointer deference exploit in
libgsf, a I/O abstraction library for GNOME.

An error within the 'tar_directory_for_file()' function could be exploited
to trigger a null pointer dereference and subsequently cause a crash via a
crafted TAR file." );
	script_tag( name: "affected", value: "'libgsf' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
1.14.30-2+deb8u1.

We recommend that you upgrade your libgsf packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gsf-1", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsf-1-114", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsf-1-114-dbg", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsf-1-common", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsf-1-dev", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsf-bin", ver: "1.14.30-2+deb8u1", rls: "DEB8" ) )){
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

