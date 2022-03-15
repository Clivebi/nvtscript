if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892166" );
	script_version( "2021-07-26T02:01:39+0000" );
	script_cve_id( "CVE-2020-10595" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-26 02:01:39 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-04-04 00:15:00 +0000 (Sat, 04 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-02 03:00:05 +0000 (Thu, 02 Apr 2020)" );
	script_name( "Debian LTS: Security Advisory for libpam-krb5 (DLA-2166-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/04/msg00000.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2166-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpam-krb5'
  package(s) announced via the DLA-2166-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The krb5 PAM module (pam_krb5.so) had a buffer overflow that
might have caused remote code execution in situations
involving supplemental prompting by a Kerberos library.
It might have overflown a buffer provided by the underlying
Kerberos library by a single '\\0' byte if an attacker
responded to a prompt with an answer of a carefully chosen
length. The effect may have ranged from heap corruption to
stack corruption depending on the structure of the underlying
Kerberos library, with unknown effects but possibly including
code execution.
This code path had not been used for normal authentication,
but only when the Kerberos library did supplemental prompting,
such as with PKINIT or when using the non-standard no_prompt
PAM configuration option." );
	script_tag( name: "affected", value: "'libpam-krb5' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
4.6-3+deb8u1. The fix was prepared by Mike Gabriel.

We recommend that you upgrade your libpam-krb5 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpam-heimdal", ver: "4.6-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-krb5", ver: "4.6-3+deb8u1", rls: "DEB8" ) )){
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

