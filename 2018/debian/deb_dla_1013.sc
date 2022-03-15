if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891013" );
	script_version( "2021-06-21T02:00:27+0000" );
	script_cve_id( "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7775", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778" );
	script_name( "Debian LTS: Security Advisory for graphite2 (DLA-1013-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 02:00:27 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-05 00:00:00 +0100 (Mon, 05 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 17:14:00 +0000 (Mon, 13 Aug 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/07/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "graphite2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.3.10-1~deb7u1.

We recommend that you upgrade your graphite2 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been found in the Graphite font rendering
engine which might result in denial of service or the execution of
arbitrary code if a malformed font file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libgraphite2-2.0.0", ver: "1.3.10-1~deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphite2-2.0.0-dbg", ver: "1.3.10-1~deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphite2-dev", ver: "1.3.10-1~deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphite2-doc", ver: "1.3.10-1~deb7u1", rls: "DEB7" ) )){
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

