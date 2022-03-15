if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892686" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2018-20060", "CVE-2019-11236", "CVE-2019-11324", "CVE-2020-26137" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-16 03:00:13 +0000 (Wed, 16 Jun 2021)" );
	script_name( "Debian LTS: Security Advisory for python-urllib3 (DLA-2686-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/06/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2686-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2686-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-urllib3'
  package(s) announced via the DLA-2686-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in python-urllib3, a HTTP
client for Python.

CVE-2018-20060

Urllib3 does not remove the Authorization HTTP header when
following a cross-origin redirect (i.e., a redirect that differs
in host, port, or scheme). This can allow for credentials in the
Authorization header to be exposed to unintended hosts or
transmitted in cleartext.

CVE-2019-11236

CRLF injection is possible if the attacker controls the request
parameter.

CVE-2019-11324

Urllib3 mishandles certain cases where the desired set of CA
certificates is different from the OS store of CA certificates,
which results in SSL connections succeeding in situations where a
verification failure is the correct outcome. This is related to
use of the ssl_context, ca_certs, or ca_certs_dir argument.

CVE-2020-26137

Urllib3 allows CRLF injection if the attacker controls the HTTP
request method, as demonstrated by inserting CR and LF control
characters in the first argument of putrequest()." );
	script_tag( name: "affected", value: "'python-urllib3' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.19.1-1+deb9u1.

We recommend that you upgrade your python-urllib3 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "python-urllib3", ver: "1.19.1-1+deb9u1", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-urllib3", ver: "1.19.1-1+deb9u1", rls: "DEB9" ) )){
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

