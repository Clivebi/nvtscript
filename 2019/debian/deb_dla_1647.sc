if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891647" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-17199" );
	script_name( "Debian LTS: Security Advisory for apache2 (DLA-1647-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-30 00:00:00 +0100 (Wed, 30 Jan 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "apache2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.4.10-10+deb8u13.

We recommend that you upgrade your apache2 packages." );
	script_tag( name: "summary", value: "Diego Angulo from ImExHS discovered an issue in the webserver apache2.
The module mod_session ignored the expiry time of sessions handled by
mod_session_cookie, because the expiry time is available only after
decoding the session and the check was already done before." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "apache2", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-bin", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-data", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-dbg", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-dev", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-doc", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-event", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-itk", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-prefork", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-mpm-worker", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-suexec", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-suexec-custom", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-suexec-pristine", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2-utils", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2.2-bin", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "apache2.2-common", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-macro", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libapache2-mod-proxy-html", ver: "2.4.10-10+deb8u13", rls: "DEB8" ) )){
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

