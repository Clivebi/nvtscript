if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704787" );
	script_version( "2021-07-27T11:00:54+0000" );
	script_cve_id( "CVE-2020-15275", "CVE-2020-25074" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-27 11:00:54 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-24 17:20:00 +0000 (Tue, 24 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-10 06:30:12 +0000 (Tue, 10 Nov 2020)" );
	script_name( "Debian: Security Advisory for moin (DSA-4787-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2020/dsa-4787.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4787-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'moin'
  package(s) announced via the DSA-4787-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Two vulnerabilities were discovered in moin, a Python clone of WikiWiki.

CVE-2020-15275
Catarina Leite discovered that moin is prone to a stored XSS
vulnerability via SVG attachments.

CVE-2020-25074
Michael Chapman discovered that moin is prone to a remote code
execution vulnerability via the cache action." );
	script_tag( name: "affected", value: "'moin' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), these problems have been fixed in
version 1.9.9-1+deb10u1.

We recommend that you upgrade your moin packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-moinmoin", ver: "1.9.9-1+deb10u1", rls: "DEB10" ) )){
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

