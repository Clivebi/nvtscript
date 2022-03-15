if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704970" );
	script_version( "2021-09-27T08:01:28+0000" );
	script_cve_id( "CVE-2021-40347" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-27 08:01:28 +0000 (Mon, 27 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-24 03:04:00 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-11 01:00:07 +0000 (Sat, 11 Sep 2021)" );
	script_name( "Debian: Security Advisory for postorius (DSA-4970-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(10|11)" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4970.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4970-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4970-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postorius'
  package(s) announced via the DSA-4970-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kevin Israel discovered that Postorius, the administrative web frontend
for Mailman 3, didn't validate whether a logged-in user owns the email
address when unsubscribing." );
	script_tag( name: "affected", value: "'postorius' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the oldstable distribution (buster), this problem has been fixed
in version 1.2.4-1+deb10u1.

For the stable distribution (bullseye), this problem has been fixed in
version 1.3.4-2+deb11u1.

We recommend that you upgrade your postorius packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python3-django-postorius", ver: "1.2.4-1+deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-django-postorius", ver: "1.3.4-2+deb11u1", rls: "DEB11" ) )){
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

