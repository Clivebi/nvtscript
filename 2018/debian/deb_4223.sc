if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704223" );
	script_version( "2021-06-18T02:36:51+0000" );
	script_cve_id( "CVE-2018-12020" );
	script_name( "Debian Security Advisory DSA 4223-1 (gnupg1 - security update)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:36:51 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-08 00:00:00 +0200 (Fri, 08 Jun 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4223.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "gnupg1 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 1.4.21-4+deb9u1.

We recommend that you upgrade your gnupg1 packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/gnupg1" );
	script_tag( name: "summary", value: "Marcus Brinkmann discovered that GnuPG performed insufficient
sanitisation of file names displayed in status messages, which could be
abused to fake the verification status of a signed email." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gnupg1", ver: "1.4.21-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnupg1-curl", ver: "1.4.21-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gnupg1-l10n", ver: "1.4.21-4+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gpgv1", ver: "1.4.21-4+deb9u1", rls: "DEB9" ) )){
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

