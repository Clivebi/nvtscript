if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892234" );
	script_version( "2020-06-05T10:36:02+0000" );
	script_cve_id( "CVE-2005-1513", "CVE-2005-1514", "CVE-2005-1515", "CVE-2020-3811", "CVE-2020-3812" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-06-05 10:36:02 +0000 (Fri, 05 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-05 03:00:15 +0000 (Fri, 05 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for netqmail (DLA-2234-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00002.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2234-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/961060" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'netqmail'
  package(s) announced via the DLA-2234-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "There were several CVE bugs reported against src:netqmail.

CVE-2005-1513

Integer overflow in the stralloc_readyplus function in qmail,
when running on 64 bit platforms with a large amount of virtual
memory, allows remote attackers to cause a denial of service
and possibly execute arbitrary code via a large SMTP request.

CVE-2005-1514

commands.c in qmail, when running on 64 bit platforms with a
large amount of virtual memory, allows remote attackers to
cause a denial of service and possibly execute arbitrary code
via a long SMTP command without a space character, which causes
an array to be referenced with a negative index.

CVE-2005-1515

Integer signedness error in the qmail_put and substdio_put
functions in qmail, when running on 64 bit platforms with a
large amount of virtual memory, allows remote attackers to
cause a denial of service and possibly execute arbitrary code
via a large number of SMTP RCPT TO commands.

CVE-2020-3811

qmail-verify as used in netqmail 1.06 is prone to a
mail-address verification bypass vulnerability.

CVE-2020-3812

qmail-verify as used in netqmail 1.06 is prone to an
information disclosure vulnerability. A local attacker can
test for the existence of files and directories anywhere in
the filesystem because qmail-verify runs as root and tests
for the existence of files in the attacker's home directory,
without dropping its privileges first." );
	script_tag( name: "affected", value: "'netqmail' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.06-6.2~deb8u1.

We recommend that you upgrade your netqmail packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "qmail", ver: "1.06-6.2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qmail-uids-gids", ver: "1.06-6.2~deb8u1", rls: "DEB8" ) )){
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

