if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890878" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2017-6298", "CVE-2017-6299", "CVE-2017-6300", "CVE-2017-6301", "CVE-2017-6302", "CVE-2017-6303", "CVE-2017-6304", "CVE-2017-6305", "CVE-2017-6801", "CVE-2017-6802" );
	script_name( "Debian LTS: Security Advisory for libytnef (DLA-878-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-18 03:29:00 +0000 (Sat, 18 May 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00036.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libytnef on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.5-4+deb7u1.

We recommend that you upgrade your libytnef packages." );
	script_tag( name: "summary", value: "CVE-2017-6298
Null Pointer Deref / calloc return value not checked

CVE-2017-6299
Infinite Loop / DoS in the TNEFFillMapi function in lib/ytnef.c

CVE-2017-6300
Buffer Overflow in version field in lib/tnef-types.h

CVE-2017-6301
Out of Bounds Reads

CVE-2017-6302
Integer Overflow

CVE-2017-6303
Invalid Write and Integer Overflow

CVE-2017-6304
Out of Bounds read

CVE-2017-6305
Out of Bounds read and write

CVE-2017-6801
Out-of-bounds access with fields of Size 0 in TNEFParse() in libytnef

CVE-2017-6802
Heap-based buffer over-read on incoming Compressed RTF Streams,
related to DecompressRTF() in libytnef" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libytnef0", ver: "1.5-4+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libytnef0-dev", ver: "1.5-4+deb7u1", rls: "DEB7" ) )){
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

