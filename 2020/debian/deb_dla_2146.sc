if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892146" );
	script_version( "2020-03-18T10:44:59+0000" );
	script_cve_id( "CVE-2019-15690" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-18 10:44:59 +0000 (Wed, 18 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-18 10:44:59 +0000 (Wed, 18 Mar 2020)" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-2146-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/03/msg00019.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2146-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/954163" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvncserver'
  package(s) announced via the DLA-2146-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "In libvncserver, through libvncclient/cursor.c, there is a possibility
of a heap overflow, as reported by Pavel Cheremushkin." );
	script_tag( name: "affected", value: "'libvncserver' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
0.9.9+dfsg2-6.1+deb8u7.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg2-6.1+deb8u7", rls: "DEB8" ) )){
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

