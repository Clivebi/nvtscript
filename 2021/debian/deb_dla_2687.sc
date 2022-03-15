if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892687" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-32917", "CVE-2021-32921" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-17 16:58:00 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 03:00:11 +0000 (Thu, 17 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for prosody (DLA-2687-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00016.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2687-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2687-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'prosody'
  package(s) announced via the DLA-2687-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two security issues have been discovered in prosody:

CVE-2021-32917

The proxy65 component allows open access by default, even if neither of the
users has an XMPP account on the local server, allowing unrestricted use of
the server's bandwidth.

CVE-2021-32921

Authentication module does not use a constant-time algorithm for comparing
certain secret strings when running under Lua 5.2 or later. This can
potentially be used in a timing attack to reveal the contents of secret
strings to an attacker." );
	script_tag( name: "affected", value: "'prosody' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
0.9.12-2+deb9u3.

We recommend that you upgrade your prosody packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "prosody", ver: "0.9.12-2+deb9u3", rls: "DEB9" ) )){
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

