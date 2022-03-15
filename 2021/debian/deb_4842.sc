if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704842" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2020-15685", "CVE-2020-16044", "CVE-2020-26976", "CVE-2021-23953", "CVE-2021-23954", "CVE-2021-23960", "CVE-2021-23964" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-11 21:09:00 +0000 (Thu, 11 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-02 04:00:12 +0000 (Tue, 02 Feb 2021)" );
	script_name( "Debian: Security Advisory for thunderbird (DSA-4842-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4842.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4842-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4842-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the DSA-4842-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Multiple security issues have been found in Thunderbird, which may lead
to the execution of arbitrary code, denial of service or an information
leak." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1:78.7.0-1~deb10u1.

We recommend that you upgrade your thunderbird packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ar", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ast", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-be", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-bg", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-br", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ca", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-cs", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-cy", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-da", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-de", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-dsb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-el", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-en-gb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-es-ar", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-es-es", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-et", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-eu", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fi", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-fy-nl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ga-ie", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-gd", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-gl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-he", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hsb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hu", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-hy-am", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-id", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-is", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-it", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ja", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-kab", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-kk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ko", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-lt", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ms", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nb-no", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-nn-no", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pt-br", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-pt-pt", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-rm", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ro", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-ru", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-si", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sq", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-sv-se", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-tr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-uk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-vi", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-zh-cn", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "lightning-l10n-zh-tw", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-all", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ar", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ast", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-be", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-bg", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-br", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ca", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-cak", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-cs", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-cy", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-da", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-de", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-dsb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-el", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-en-gb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-es-ar", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-es-es", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-et", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-eu", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fi", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-fy-nl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ga-ie", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-gd", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-gl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-he", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hsb", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hu", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-hy-am", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-id", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-is", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-it", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ja", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ka", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-kab", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-kk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ko", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-lt", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ms", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nb-no", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-nn-no", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pt-br", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-pt-pt", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-rm", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ro", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-ru", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-si", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sl", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sq", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-sv-se", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-tr", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-uk", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-uz", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-vi", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-zh-cn", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "thunderbird-l10n-zh-tw", ver: "1:78.7.0-1~deb10u1", rls: "DEB10" ) )){
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

