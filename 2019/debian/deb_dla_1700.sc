if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891700" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-19518" );
	script_name( "Debian LTS: Security Advisory for uw-imap (DLA-1700-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-01 00:00:00 +0100 (Fri, 01 Mar 2019)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00001.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "uw-imap on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
8:2007f~dfsg-4+deb8u1.

We recommend that you upgrade your uw-imap packages." );
	script_tag( name: "summary", value: "vulnerability was discovered in uw-imap, the University of Washington
IMAP Toolkit, that might allow remote attackers to execute arbitrary OS
commands if the IMAP server name is untrusted input (e.g., entered by a
user of a web application) and if rsh has been replaced by a program
with different argument semantics.

This update disables access to IMAP mailboxes through running imapd over
rsh, and therefore ssh for users of the client application. Code which
uses the library can still enable it with tcp_parameters() after making
sure that the IMAP server name is sanitized." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libc-client2007e", ver: "8:2007f~dfsg-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libc-client2007e-dev", ver: "8:2007f~dfsg-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "mlock", ver: "8:2007f~dfsg-4+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "uw-mailutils", ver: "8:2007f~dfsg-4+deb8u1", rls: "DEB8" ) )){
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

