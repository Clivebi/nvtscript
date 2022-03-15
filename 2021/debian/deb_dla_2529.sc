if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892529" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-3181" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-17 17:08:00 +0000 (Wed, 17 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-21 04:00:06 +0000 (Thu, 21 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for mutt (DLA-2529-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00017.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2529-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/980326" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mutt'
  package(s) announced via the DLA-2529-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "rfc822.c in Mutt through 2.0.4 allows remote attackers to
cause a denial of service (mailbox unavailability) by sending
email messages with sequences of semicolon characters in
RFC822 address fields (aka terminators of empty groups).

A small email message from the attacker can cause large
memory consumption, and the victim may then be unable to
see email messages from other persons." );
	script_tag( name: "affected", value: "'mutt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
1.7.2-1+deb9u5.

We recommend that you upgrade your mutt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mutt", ver: "1.7.2-1+deb9u5", rls: "DEB9" ) )){
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

