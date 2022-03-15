if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892441" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2018-1000671", "CVE-2020-26880" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-09 03:15:00 +0000 (Sun, 09 May 2021)" );
	script_tag( name: "creation_date", value: "2020-11-10 04:00:20 +0000 (Tue, 10 Nov 2020)" );
	script_name( "Debian LTS: Security Advisory for sympa (DLA-2441-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/11/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2441-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/908165" );
	script_xref( name: "URL", value: "https://bugs.debian.org/972189" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sympa'
  package(s) announced via the DLA-2441-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A privilege escalation was discovered in Sympa, a modern mailing list
manager. It is fixed when Sympa is used in conjunction with common
MTAs (such as Exim or Postfix) by disabling a setuid executable,
although no fix is currently available for all environments (such as
sendmail). Additionally, an open-redirect vulnerability was
discovered and fixed.

CVE-2020-26880

Sympa allows a local privilege escalation from the sympa user
account to full root access by modifying the sympa.conf
configuration file (which is owned by sympa) and parsing it
through the setuid sympa_newaliases-wrapper executable.

CVE-2018-1000671

Sympa contains a CWE-601: URL Redirection to Untrusted Site ('Open
Redirect') vulnerability in The 'referer' parameter of the
wwsympa.fcgi login action. that can result in Open redirection and
reflected XSS via data URIs." );
	script_tag( name: "affected", value: "'sympa' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
6.2.16~dfsg-3+deb9u4.

We recommend that you upgrade your sympa packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sympa", ver: "6.2.16~dfsg-3+deb9u4", rls: "DEB9" ) )){
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

