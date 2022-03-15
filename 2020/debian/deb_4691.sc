if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704691" );
	script_version( "2021-07-28T02:00:54+0000" );
	script_cve_id( "CVE-2020-10955", "CVE-2020-12244" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-28 02:00:54 +0000 (Wed, 28 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-14 19:15:00 +0000 (Sun, 14 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-05-23 03:00:06 +0000 (Sat, 23 May 2020)" );
	script_name( "Debian: Security Advisory for pdns-recursor (DSA-4691-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4691.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4691-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pdns-recursor'
  package(s) announced via the DSA-4691-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabiliites have been discovered in PDNS Recursor, a resolving
name server, a traffic amplification attack against third party
authoritative name servers (NXNSAttack) and insufficient validation of
NXDOMAIN responses lacking an SOA.

The version of pdns-recursor in the oldstable distribution (stretch) is
no longer supported. If these security issues affect your setup, you
should upgrade to the stable distribution (buster)." );
	script_tag( name: "affected", value: "'pdns-recursor' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 4.1.11-1+deb10u1.

We recommend that you upgrade your pdns-recursor packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "pdns-recursor", ver: "4.1.11-1+deb10u1", rls: "DEB10" ) )){
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

