if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703798" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_cve_id( "CVE-2017-6307", "CVE-2017-6308", "CVE-2017-6309", "CVE-2017-6310" );
	script_name( "Debian Security Advisory DSA 3798-1 (tnef - security update)" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-01 00:00:00 +0100 (Wed, 01 Mar 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 18:21:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3798.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "tnef on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 1.4.9-1+deb8u1.

We recommend that you upgrade your tnef packages." );
	script_tag( name: "summary", value: "Eric Sesterhenn, from X41 D-Sec GmbH, discovered several
vulnerabilities in tnef, a tool used to unpack MIME attachments of
type application/ms-tnef
. Multiple heap overflows, type confusions
and out of bound reads and writes could be exploited by tricking a
user into opening a malicious attachment. This would result in denial
of service via application crash, or potential arbitrary code
execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "tnef", ver: "1.4.9-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

