if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703868" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_cve_id( "CVE-2017-9287" );
	script_name( "Debian Security Advisory DSA 3868-1 (openldap - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-30 00:00:00 +0200 (Tue, 30 May 2017)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3868.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "openldap on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.4.40+dfsg-1+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 2.4.44+dfsg-5.

We recommend that you upgrade your openldap packages." );
	script_tag( name: "summary", value: "Karsten Heymann discovered that the OpenLDAP directory server can be
crashed by performing a paged search with a page size of 0, resulting in
denial of service. This vulnerability is limited to the MDB storage
backend." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap-2.4-2-dbg", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd-dbg", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "slapd-smbk5pwd", ver: "2.4.40+dfsg-1+deb8u3", rls: "DEB8" ) ) != NULL){
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

