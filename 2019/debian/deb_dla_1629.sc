if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891629" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2019-3498" );
	script_name( "Debian LTS: Security Advisory for python-django (DLA-1629-1)" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-07 00:00:00 +0100 (Mon, 07 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 13:11:00 +0000 (Tue, 23 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00005.html" );
	script_xref( name: "URL", value: "https://www.djangoproject.com/weblog/2019/jan/04/security-releases/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "python-django on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in python-django
version 1.7.11-1+deb8u4.

We recommend that you upgrade your python-django packages." );
	script_tag( name: "summary", value: "It was discovered that there was a content-spoofing vulnerability in the
default 404 pages in the Django web development framework.

Please see the references for more information." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-django", ver: "1.7.11-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-common", ver: "1.7.11-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-django-doc", ver: "1.7.11-1+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django", ver: "1.7.11-1+deb8u4", rls: "DEB8" ) )){
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

