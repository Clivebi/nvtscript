if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891343" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2018-6358", "CVE-2018-7867", "CVE-2018-7868", "CVE-2018-7870", "CVE-2018-7871", "CVE-2018-7872", "CVE-2018-7875", "CVE-2018-9165" );
	script_name( "Debian LTS: Security Advisory for ming (DLA-1343-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-09 00:00:00 +0200 (Mon, 09 Apr 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00008.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ming on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.4.4-1.1+deb7u8.

We recommend that you upgrade your ming packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Ming:

CVE-2018-6358

Heap-based buffer overflow vulnerability in the printDefineFont2 function
(util/listfdb.c). Remote attackers might leverage this vulnerability to
cause a denial of service via a crafted swf file.

CVE-2018-7867

Heap-based buffer overflow vulnerability in the getString function
(util/decompile.c) during a RegisterNumber sprintf. Remote attackers might
leverage this vulnerability to cause a denial of service via a crafted swf
file.

CVE-2018-7868

Heap-based buffer over-read vulnerability in the getName function
(util/decompile.c) for CONSTANT8 data. Remote attackers might leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7870

Invalid memory address dereference in the getString function
(util/decompile.c) for CONSTANT16 data. Remote attackers might leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7871

Heap-based buffer over-read vulnerability in the getName function
(util/decompile.c) for CONSTANT16 data. Remote attackers might leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7872

Invalid memory address dereference in the getName function
(util/decompile.c) for CONSTANT16 data. Remote attackers might leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-7875

Heap-based buffer over-read vulnerability in the getName function
(util/decompile.c) for CONSTANT8 data. Remote attackers might leverage this
vulnerability to cause a denial of service via a crafted swf file.

CVE-2018-9165

The pushdup function (util/decompile.c) performs shallow copy of String
elements (instead of deep copy), allowing simultaneous change of multiple
elements of the stack, which indirectly makes the library vulnerable to a
NULL pointer dereference in getName (util/decompile.c). Remote attackers
might leverage this vulnerability to cause dos via a crafted swf file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libming-dev", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libming-util", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libming1", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswf-perl", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ming-fonts-dejavu", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ming-fonts-opensymbol", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ming", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-ming", ver: "0.4.4-1.1+deb7u8", rls: "DEB7" ) )){
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

