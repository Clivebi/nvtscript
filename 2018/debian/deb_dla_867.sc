if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890867" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2017-6829", "CVE-2017-6830", "CVE-2017-6831", "CVE-2017-6832", "CVE-2017-6833", "CVE-2017-6834", "CVE-2017-6835", "CVE-2017-6836", "CVE-2017-6837", "CVE-2017-6838", "CVE-2017-6839" );
	script_name( "Debian LTS: Security Advisory for audiofile (DLA-867-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "audiofile on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.3.4-2+deb7u1.

We recommend that you upgrade your audiofile packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities has been found in audiofile.

CVE-2017-6829

Allows remote attackers to cause a denial of service (crash) via a
crafted file.

CVE-2017-6830, CVE-2017-6834, CVE-2017-6831, CVE-2017-6832, CVE-2017-6838,
CVE-2017-6839, CVE-2017-6836

Heap-based buffer overflow in that allows remote attackers to cause
a denial of service (crash) via a crafted file.

CVE-2017-6833, CVE-2017-6835

The runPull function allows remote attackers to cause a denial of
service (divide-by-zero error and crash) via a crafted file.

CVE-2017-6837

Allows remote attackers to cause a denial of service (crash) via
vectors related to a large number of coefficients." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "audiofile-tools", ver: "0.3.4-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaudiofile-dbg", ver: "0.3.4-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaudiofile-dev", ver: "0.3.4-2+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libaudiofile1", ver: "0.3.4-2+deb7u1", rls: "DEB7" ) )){
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
