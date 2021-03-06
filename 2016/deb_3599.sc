if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703599" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-2335" );
	script_name( "Debian Security Advisory DSA 3599-1 (p7zip - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-09 00:00:00 +0200 (Thu, 09 Jun 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3599.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(8|9)" );
	script_tag( name: "affected", value: "p7zip on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 9.20.1~dfsg.1-4.1+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 15.14.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in
version 15.14.1+dfsg-2.

We recommend that you upgrade your p7zip packages." );
	script_tag( name: "summary", value: "Marcin Icewall
Noga of Cisco Talos discovered an out-of-bound read
vulnerability in the CInArchive::ReadFileItem method in p7zip, a 7zr
file archiver with high compression ratio. A remote attacker can take
advantage of this flaw to cause a denial-of-service or, potentially the
execution of arbitrary code with the privileges of the user running
p7zip, if a specially crafted UDF file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "p7zip", ver: "9.20.1~dfsg.1-4.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "p7zip-full", ver: "9.20.1~dfsg.1-4.1+deb8u2", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "p7zip", ver: "15.14.1+dfsg-2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "p7zip-full", ver: "15.14.1+dfsg-2", rls: "DEB9" ) ) != NULL){
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

