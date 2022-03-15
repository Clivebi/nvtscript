if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702599" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-0743" );
	script_name( "Debian Security Advisory DSA 2599-1 (nss - mis-issued intermediates)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-06 00:00:00 +0100 (Sun, 06 Jan 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2599.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "nss on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze6.

For the testing distribution (wheezy), this problem has been fixed in
version 2:3.13.6-2.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.14.1.with.ckbi.1.93-1.

We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "Google, Inc. discovered that the TurkTrust certification authority
included in the Network Security Service libraries (nss) mis-issued
two intermediate CAs which could be used to generate rogue end-entity
certificates. This update explicitly distrusts those two intermediate
CAs. The two existing TurkTrust root CAs remain active." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.12.8-1+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d-dbg", ver: "3.12.8-1+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "3.12.8-1+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "3.12.8-1+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3", ver: "2:3.13.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "2:3.13.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dbg", ver: "2:3.13.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "2:3.13.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "2:3.13.6-2", rls: "DEB7" ) ) != NULL){
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

