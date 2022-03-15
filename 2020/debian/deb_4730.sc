if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704730" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-4054" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 20:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-07-20 03:00:07 +0000 (Mon, 20 Jul 2020)" );
	script_name( "Debian: Security Advisory for ruby-sanitize (DSA-4730-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4730.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4730-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ruby-sanitize'
  package(s) announced via the DSA-4730-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Michal Bentkowski discovered that ruby-sanitize, a whitelist-based HTML
sanitizer, is prone to a HTML sanitization bypass vulnerability when
using the relaxed
or a custom config allowing certain elements.
Content in an or element may not be sanitized correctly even
if math and svg are not in the allowlist." );
	script_tag( name: "affected", value: "'ruby-sanitize' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4.6.6-2.1~deb10u1.

We recommend that you upgrade your ruby-sanitize packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "ruby-sanitize", ver: "4.6.6-2.1~deb10u1", rls: "DEB10" ) )){
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

