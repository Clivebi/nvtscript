if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891600" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2015-8915", "CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689", "CVE-2017-14166", "CVE-2017-14501", "CVE-2017-14502", "CVE-2017-14503", "CVE-2017-5601" );
	script_name( "Debian LTS: Security Advisory for libarchive (DLA-1600-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-30 00:00:00 +0100 (Fri, 30 Nov 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-30 11:29:00 +0000 (Fri, 30 Nov 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00037.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libarchive on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
3.1.2-11+deb8u4.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "summary", value: "Multiple security vulnerabilities were found in libarchive, a
multi-format archive and compression library. Heap-based buffer
over-reads, NULL pointer dereferences and out-of-bounds reads allow
remote attackers to cause a denial-of-service (application crash) via
specially crafted archive files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.1.2-11+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "bsdtar", ver: "3.1.2-11+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive-dev", ver: "3.1.2-11+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libarchive13", ver: "3.1.2-11+deb8u4", rls: "DEB8" ) )){
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

