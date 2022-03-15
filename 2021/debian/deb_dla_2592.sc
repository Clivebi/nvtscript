if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892592" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2017-15041", "CVE-2018-16873", "CVE-2018-16874", "CVE-2019-16276", "CVE-2019-17596", "CVE-2019-9741", "CVE-2021-3114" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-19 20:11:00 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-03-14 04:00:16 +0000 (Sun, 14 Mar 2021)" );
	script_name( "Debian LTS: Security Advisory for golang-1.8 (DLA-2592-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/03/msg00015.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2592-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2592-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/924630" );
	script_xref( name: "URL", value: "https://bugs.debian.org/941173" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942628" );
	script_xref( name: "URL", value: "https://bugs.debian.org/942629" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang-1.8'
  package(s) announced via the DLA-2592-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Go programming
language. An attacker could trigger a denial-of-service (DoS), bypasss
access control, and execute arbitrary code on the developer's
computer.

CVE-2017-15041

Go allows 'go get' remote command execution. Using custom
domains, it is possible to arrange things so that
example.com/pkg1 points to a Subversion repository but
example.com/pkg1/pkg2 points to a Git repository. If the
Subversion repository includes a Git checkout in its pkg2
directory and some other work is done to ensure the proper
ordering of operations, 'go get' can be tricked into reusing this
Git checkout for the fetch of code from pkg2. If the Subversion
repository's Git checkout has malicious commands in .git/hooks/,
they will execute on the system running 'go get.'

CVE-2018-16873

The 'go get' command is vulnerable to remote code execution when
executed with the -u flag and the import path of a malicious Go
package, as it may treat the parent directory as a Git repository
root, containing malicious configuration.

CVE-2018-16874

The 'go get' command is vulnerable to directory traversal when
executed with the import path of a malicious Go package which
contains curly braces (both '{' and '}' characters). The attacker
can cause an arbitrary filesystem write, which can lead to code
execution.

CVE-2019-9741

In net/http, CRLF injection is possible if the attacker controls a
url parameter, as demonstrated by the second argument to
http.NewRequest with \\r\\n followed by an HTTP header or a Redis
command.

CVE-2019-16276

Go allows HTTP Request Smuggling.

CVE-2019-17596

Go can panic upon an attempt to process network traffic containing
an invalid DSA public key. There are several attack scenarios,
such as traffic from a client to a server that verifies client
certificates.

CVE-2021-3114

crypto/elliptic/p224.go can generate incorrect outputs, related to
an underflow of the lowest limb during the final complete
reduction in the P-224 field." );
	script_tag( name: "affected", value: "'golang-1.8' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
1.8.1-1+deb9u3.

We recommend that you upgrade your golang-1.8 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8", ver: "1.8.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-doc", ver: "1.8.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-go", ver: "1.8.1-1+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "golang-1.8-src", ver: "1.8.1-1+deb9u3", rls: "DEB9" ) )){
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

