if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702872" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0004" );
	script_name( "Debian Security Advisory DSA 2872-1 (udisks - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-10 00:00:00 +0100 (Mon, 10 Mar 2014)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2872.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "udisks on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.0.1+git20100614-3squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 1.0.4-7wheezy1.

For the unstable distribution (sid), this problem has been fixed in
version 1.0.5-1.

We recommend that you upgrade your udisks packages." );
	script_tag( name: "summary", value: "Florian Weimer discovered a buffer overflow in udisks's mount path
parsing code which may result in privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "udisks", ver: "1.0.1+git20100614-3squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "udisks-doc", ver: "1.0.1+git20100614-3squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "udisks", ver: "1.0.4-7wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "udisks-doc", ver: "1.0.4-7wheezy1", rls: "DEB7" ) ) != NULL){
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

