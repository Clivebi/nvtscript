if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891524" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-18258", "CVE-2018-14404", "CVE-2018-14567", "CVE-2018-9251" );
	script_name( "Debian LTS: Security Advisory for libxml2 (DLA-1524-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-28 00:00:00 +0200 (Fri, 28 Sep 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-10 01:15:00 +0000 (Thu, 10 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00035.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libxml2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
2.9.1+dfsg1-5+deb8u7.

We recommend that you upgrade your libxml2 packages." );
	script_tag( name: "summary", value: "CVE-2018-14404
Fix of a NULL pointer dereference which might result in a crash and
thus in a denial of service.

CVE-2018-14567 and CVE-2018-9251
Approval in LZMA error handling which prevents an infinite loop.

CVE-2017-18258
Limit available memory to 100MB to avoid exhaustive memory
consumption by malicious files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libxml2", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-dev", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-doc", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxml2-utils-dbg", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-libxml2-dbg", ver: "2.9.1+dfsg1-5+deb8u7", rls: "DEB8" ) )){
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

