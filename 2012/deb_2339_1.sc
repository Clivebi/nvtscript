if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70553" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3640" );
	script_version( "2020-05-14T10:14:42+0000" );
	script_tag( name: "last_modification", value: "2020-05-14 10:14:42 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2012-02-11 02:28:18 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2339-1 (nss)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202339-1" );
	script_tag( name: "insight", value: "This update to the NSS cryptographic libraries revokes the trust in the
DigiCert Sdn. Bhd certificate authority.

This update also fixes an insecure load path for pkcs11.txt configuration
file (CVE-2011-3640).

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny7.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze4.

For the unstable distribution (sid), this problem has been fixed in
version 3.13.1.with.ckbi.1.88-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your nss packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to nss
announced via advisory DSA 2339-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.12.3.1-0lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d-dbg", ver: "3.12.3.1-0lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "3.12.3.1-0lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "3.12.3.1-0lenny7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d", ver: "3.12.8-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-1d-dbg", ver: "3.12.8-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-dev", ver: "3.12.8-1+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnss3-tools", ver: "3.12.8-1+squeeze4", rls: "DEB6" ) ) != NULL){
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

