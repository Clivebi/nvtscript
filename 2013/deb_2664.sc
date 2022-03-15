if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702664" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1762" );
	script_name( "Debian Security Advisory DSA 2664-1 (stunnel4 - buffer overflow)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-05-02 00:00:00 +0200 (Thu, 02 May 2013)" );
	script_tag( name: "cvss_base", value: "6.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2664.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "stunnel4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 3:4.29-1+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 3:4.53-1.1.

For the unstable distribution (sid), this problem has been fixed in
version 3:4.53-1.1.

We recommend that you upgrade your stunnel4 packages." );
	script_tag( name: "summary", value: "Stunnel, a program designed to work as an universal SSL tunnel for
network daemons, is prone to a buffer overflow vulnerability when using
the Microsoft NT LAN Manager (NTLM) authentication
(protocolAuthentication = NTLM) together with the connect protocol method (protocol = connect). With these prerequisites
and using stunnel4 in SSL client mode (client = yes
) on a 64 bit
host, an attacker could possibly execute arbitrary code with the
privileges of the stunnel process, if the attacker can either control
the specified proxy server or perform man-in-the-middle attacks on the
tcp session between stunnel and the proxy sever.

Note that for the testing distribution (wheezy) and the unstable
distribution (sid), stunnel4 is compiled with stack smashing protection
enabled, which should help protect against arbitrary code execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "stunnel", ver: "3:4.29-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "stunnel4", ver: "3:4.29-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "stunnel4", ver: "3:4.53-1.1", rls: "DEB7" ) ) != NULL){
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

