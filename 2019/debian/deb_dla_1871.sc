if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891871" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2017-11109", "CVE-2017-17087", "CVE-2019-12735" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-08-04 02:00:08 +0000 (Sun, 04 Aug 2019)" );
	script_name( "Debian LTS: Security Advisory for vim (DLA-1871-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00003.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1871-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/867720" );
	script_xref( name: "URL", value: "https://bugs.debian.org/930020" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'vim'
  package(s) announced via the DLA-1871-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several minor issues have been fixed in vim, a highly configurable
text editor.

CVE-2017-11109

Vim allows attackers to cause a denial of service (invalid free)
or possibly have unspecified other impact via a crafted source
(aka -S) file.

CVE-2017-17087

Vim sets the group ownership of a .swp file to the editor's
primary group (which may be different from the group ownership of
the original file), which allows local users to obtain sensitive
information by leveraging an applicable group membership.

CVE-2019-12735

Vim did not restrict the `:source!` command when executed in a
sandbox." );
	script_tag( name: "affected", value: "'vim' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2:7.4.488-7+deb8u4.

We recommend that you upgrade your vim packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "vim", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-athena", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-common", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-dbg", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-doc", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gnome", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gtk", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-gui-common", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-lesstif", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-nox", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-runtime", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vim-tiny", ver: "2:7.4.488-7+deb8u4", rls: "DEB8" ) )){
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

