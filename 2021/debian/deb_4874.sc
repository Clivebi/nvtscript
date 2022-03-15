if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704874" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23984", "CVE-2021-23987" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 14:15:00 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-25 04:00:09 +0000 (Thu, 25 Mar 2021)" );
	script_name( "Debian: Security Advisory for firefox-esr (DSA-4874-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4874.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4874-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4874-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox-esr'
  package(s) announced via the DSA-4874-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues have been found in the Mozilla Firefox
web browser, which could potentially result in the execution
of arbitrary code, information disclosure or spoofing attacks." );
	script_tag( name: "affected", value: "'firefox-esr' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 78.9.0esr-1~deb10u1.

We recommend that you upgrade your firefox-esr packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ach", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-af", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-all", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-an", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ar", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ast", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-az", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-be", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-bg", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-bn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-br", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-bs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ca", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ca-valencia", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-cak", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-cs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-cy", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-da", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-de", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-dsb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-el", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-en-ca", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-en-gb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-eo", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-es-ar", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-es-cl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-es-es", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-es-mx", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-et", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-eu", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-fa", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ff", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-fi", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-fr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-fy-nl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ga-ie", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-gd", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-gl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-gn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-gu-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-he", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-hi-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-hr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-hsb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-hu", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-hy-am", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ia", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-id", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-is", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-it", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ja", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ka", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-kab", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-kk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-km", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-kn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ko", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-lij", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-lt", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-lv", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-mk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-mr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ms", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-my", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-nb-no", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ne-np", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-nl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-nn-no", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-oc", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-pa-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-pl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-pt-br", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-pt-pt", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-rm", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ro", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ru", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-si", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-sk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-sl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-son", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-sq", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-sr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-sv-se", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ta", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-te", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-th", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-tl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-tr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-trs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-uk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-ur", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-uz", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-vi", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-xh", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-zh-cn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "firefox-esr-l10n-zh-tw", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ach", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-af", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-all", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-an", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ar", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ast", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-az", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-be", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-bg", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-bn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-br", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-bs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ca", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ca-valencia", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-cak", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-cs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-cy", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-da", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-de", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-dsb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-el", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-en-ca", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-en-gb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-eo", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-es-ar", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-es-cl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-es-es", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-es-mx", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-et", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-eu", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-fa", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ff", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-fi", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-fr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-fy-nl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ga-ie", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-gd", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-gl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-gn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-gu-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-he", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-hi-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-hr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-hsb", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-hu", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-hy-am", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ia", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-id", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-is", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-it", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ja", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ka", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-kab", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-kk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-km", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-kn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ko", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-lij", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-lt", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-lv", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-mk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-mr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ms", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-my", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-nb-no", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ne-np", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-nl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-nn-no", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-oc", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-pa-in", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-pl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-pt-br", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-pt-pt", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-rm", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ro", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ru", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-si", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-sk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-sl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-son", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-sq", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-sr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-sv-se", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ta", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-te", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-th", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-tl", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-tr", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-trs", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-uk", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-ur", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-uz", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-vi", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-xh", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-zh-cn", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "iceweasel-l10n-zh-tw", ver: "78.9.0esr-1~deb10u1", rls: "DEB10" ) )){
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

