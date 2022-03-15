if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891133" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-11704", "CVE-2017-11728", "CVE-2017-11729", "CVE-2017-11730", "CVE-2017-11731", "CVE-2017-11734" );
	script_name( "Debian LTS: Security Advisory for ming (DLA-1133-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/10/msg00020.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "ming on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1:0.4.4-1.1+deb7u4.

We recommend that you upgrade your ming packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in Ming:

CVE-2017-11704

Heap-based buffer over-read in the function decompileIF in util/decompile.c
in Ming <= 0.4.8, which allows attackers to cause a denial of service via a
crafted file.

CVE-2017-11728

Heap-based buffer over-read in the function OpCode (called from
decompileSETMEMBER) in util/decompile.c in Ming <= 0.4.8, which allows
attackers to cause a denial of service via a crafted file.

CVE-2017-11729

Heap-based buffer over-read in the function OpCode (called from
decompileINCR_DECR line 1440) in util/decompile.c in Ming <= 0.4.8, which
allows attackers to cause a denial of service via a crafted file.

CVE-2017-11730

Heap-based buffer over-read in the function OpCode (called from
decompileINCR_DECR line 1474) in util/decompile.c in Ming <= 0.4.8, which
allows attackers to cause a denial of service via a crafted file.

CVE-2017-11731

Invalid memory read in the function OpCode (called from isLogicalOp and
decompileIF) in util/decompile.c in Ming <= 0.4.8, which allows attackers
to cause a denial of service via a crafted file.

CVE-2017-11734

Heap-based buffer over-read in the function decompileCALLFUNCTION in
util/decompile.c in Ming <= 0.4.8, which allows attackers to cause a denial of
service via a crafted file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libming-dev", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libming-util", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libming1", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libswf-perl", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ming-fonts-dejavu", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ming-fonts-opensymbol", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "php5-ming", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-ming", ver: "1:0.4.4-1.1+deb7u4", rls: "DEB7" ) )){
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

