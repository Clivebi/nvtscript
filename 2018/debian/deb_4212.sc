if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704212" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-11235" );
	script_name( "Debian Security Advisory DSA 4212-1 (git - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-29 00:00:00 +0200 (Tue, 29 May 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-02 00:15:00 +0000 (Sat, 02 May 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4212.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "git on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 1:2.1.4-2.1+deb8u6.

For the stable distribution (stretch), this problem has been fixed in
version 1:2.11.0-3+deb9u3.

We recommend that you upgrade your git packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/git" );
	script_tag( name: "summary", value: "Etienne Stalmans discovered that git, a fast, scalable, distributed
revision control system, is prone to an arbitrary code execution
vulnerability exploitable via specially crafted submodule names in a
.gitmodules file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "git", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-all", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-core", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-el", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-email", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-man", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitk", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.1.4-2.1+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-all", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-arch", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-core", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-cvs", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-run", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-daemon-sysvinit", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-doc", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-el", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-email", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-gui", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-man", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-mediawiki", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "git-svn", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitk", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gitweb", ver: "1:2.11.0-3+deb9u3", rls: "DEB9" ) )){
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

