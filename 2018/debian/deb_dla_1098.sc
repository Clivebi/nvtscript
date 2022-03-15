if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891098" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-2923", "CVE-2017-2924" );
	script_name( "Debian LTS: Security Advisory for freexl (DLA-1098-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-25 15:26:00 +0000 (Fri, 25 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "freexl on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.0.0b-1+deb7u4.

We recommend that you upgrade your freexl packages." );
	script_tag( name: "summary", value: "The Cisco Talos team reported two sensitive security issues affecting
FreeXL-1.0.3 and any previous version.

CVE-2017-2923

An exploitable heap based buffer overflow vulnerability exists in
the read_biff_next_record function of FreeXL 1.0.3. A specially
crafted XLS file can cause a memory corruption resulting in remote
code execution. An attacker can send malicious XLS file to trigger
this vulnerability.

CVE-2017-2924

An exploitable heap-based buffer overflow vulnerability exists in
the read_legacy_biff function of FreeXL 1.0.3. A specially crafted
XLS file can cause a memory corruption resulting in remote code
execution. An attacker can send malicious XLS file to trigger this
vulnerability." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libfreexl-dev", ver: "1.0.0b-1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreexl1", ver: "1.0.0b-1+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreexl1-dbg", ver: "1.0.0b-1+deb7u4", rls: "DEB7" ) )){
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

