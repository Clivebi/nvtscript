if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704829" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-26262" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 03:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-12 04:00:09 +0000 (Tue, 12 Jan 2021)" );
	script_name( "Debian: Security Advisory for coturn (DSA-4829-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4829.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4829-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'coturn'
  package(s) announced via the DSA-4829-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A flaw was discovered in coturn, a TURN and STUN server for VoIP. By
default coturn does not allow peers on the loopback addresses
(127.x.x.x and ::1). A remote attacker can bypass the protection via a
specially crafted request using a peer address of 0.0.0.0
and trick
coturn in relaying to the loopback interface. If listening on IPv6 the
loopback interface can also be reached by using either [::1] or [::] as
the address." );
	script_tag( name: "affected", value: "'coturn' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4.5.1.1-1.1+deb10u2.

We recommend that you upgrade your coturn packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "coturn", ver: "4.5.1.1-1.1+deb10u2", rls: "DEB10" ) )){
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

