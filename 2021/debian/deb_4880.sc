if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704880" );
	script_version( "2021-08-25T06:00:59+0000" );
	script_cve_id( "CVE-2021-28957" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 06:00:59 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 04:15:00 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-03-30 03:00:07 +0000 (Tue, 30 Mar 2021)" );
	script_name( "Debian: Security Advisory for lxml (DSA-4880-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB10" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2021/dsa-4880.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DSA-4880-1" );
	script_xref( name: "Advisory-ID", value: "DSA-4880-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lxml'
  package(s) announced via the DSA-4880-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Kevin Chung discovered that lxml, a Python binding for the libxml2 and
libxslt libraries, did not properly sanitize its input. This would
allow a malicious user to mount a cross-site scripting attack." );
	script_tag( name: "affected", value: "'lxml' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For the stable distribution (buster), this problem has been fixed in
version 4.3.2-1+deb10u3.

We recommend that you upgrade your lxml packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-lxml", ver: "4.3.2-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-dbg", ver: "4.3.2-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python-lxml-doc", ver: "4.3.2-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml", ver: "4.3.2-1+deb10u3", rls: "DEB10" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-lxml-dbg", ver: "4.3.2-1+deb10u3", rls: "DEB10" ) )){
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

