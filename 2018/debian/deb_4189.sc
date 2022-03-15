if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704189" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2018-1000178", "CVE-2018-1000179" );
	script_name( "Debian Security Advisory DSA 4189-1 (quassel - security update)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-02 00:00:00 +0200 (Wed, 02 May 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-26 22:15:00 +0000 (Mon, 26 Oct 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4189.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB[89]" );
	script_tag( name: "affected", value: "quassel on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1:0.10.0-2.3+deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 1:0.12.4-2+deb9u1.

We recommend that you upgrade your quassel packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/quassel" );
	script_tag( name: "summary", value: "Two vulnerabilities were found in the Quassel IRC client, which could
result in the execution of arbitrary code or denial of service.

Note that you need to restart the quasselcore
service after upgrading
the Quassel packages." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "quassel", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-client", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-client-kde4", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-core", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-data", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-data-kde4", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-kde4", ver: "1:0.10.0-2.3+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-client", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-client-kde4", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-core", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-data", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "quassel-kde4", ver: "1:0.12.4-2+deb9u1", rls: "DEB9" ) )){
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

