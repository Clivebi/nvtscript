if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704782" );
	script_version( "2021-07-27T02:00:54+0000" );
	script_cve_id( "CVE-2020-25692" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 02:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-08 12:15:00 +0000 (Fri, 08 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:00:22 +0000 (Tue, 03 Nov 2020)" );
	script_name( "Debian: Security Advisory for openldap (DSA-4782-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4782.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4782-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openldap'
  package(s) announced via the DSA-4782-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability in the handling of normalization with modrdn was
discovered in OpenLDAP, a free implementation of the Lightweight
Directory Access Protocol. An unauthenticated remote attacker can use
this flaw to cause a denial of service (slapd daemon crash) via a
specially crafted packet." );
	script_tag( name: "affected", value: "'openldap' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 2.4.47+dfsg-3+deb10u3.

We recommend that you upgrade your openldap packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ldap-utils", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap-2.4-2", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap-common", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libldap2-dev", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd-contrib", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapd-smbk5pwd", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "slapi-dev", ver: "2.4.47+dfsg-3+deb10u3", rls: "DEB10" ) )){
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
exit( 0 );

