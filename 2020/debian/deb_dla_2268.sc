if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892268" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2020-14093", "CVE-2020-14954" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 22:15:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-07-01 03:02:41 +0000 (Wed, 01 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for mutt (DLA-2268-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00039.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2268-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/962897" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mutt'
  package(s) announced via the DLA-2268-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities have been discovered in mutt, a console email client.

CVE-2020-14093

Mutt allowed an IMAP fcc/postpone man-in-the-middle attack via a
PREAUTH response.

CVE-2020-14954

Mutt had a STARTTLS buffering issue that affected IMAP, SMTP, and
POP3. When a server had sent a 'begin TLS' response, the client read
additional data (e.g., from a man-in-the-middle attacker) and
evaluated it in a TLS context, aka 'response injection.'" );
	script_tag( name: "affected", value: "'mutt' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.5.23-3+deb8u2.

We recommend that you upgrade your mutt packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "mutt", ver: "1.5.23-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mutt-dbg", ver: "1.5.23-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mutt-patched", ver: "1.5.23-3+deb8u2", rls: "DEB8" ) )){
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

